#include "vfdual/dxgi_desktop_capture.hpp"
#include "vfdual/dxgi_frame_semantics.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <chrono>
#include <algorithm>
#include <limits>
#include <vector>

namespace vfdual {
namespace {
using Microsoft::WRL::ComPtr;
[[nodiscard]] std::uint64_t qpc_now() noexcept {
    LARGE_INTEGER value{}; QueryPerformanceCounter(&value); return static_cast<std::uint64_t>(value.QuadPart);
}

class AcquiredFrameGuard final {
public:
    explicit AcquiredFrameGuard(IDXGIOutputDuplication* duplication) noexcept : duplication_(duplication) {}
    ~AcquiredFrameGuard() { (void)release(); }
    AcquiredFrameGuard(const AcquiredFrameGuard&) = delete;
    AcquiredFrameGuard& operator=(const AcquiredFrameGuard&) = delete;

    [[nodiscard]] HRESULT release() noexcept {
        if (duplication_ == nullptr) return S_OK;
        IDXGIOutputDuplication* duplication = duplication_;
        duplication_ = nullptr;
        return duplication->ReleaseFrame();
    }

private:
    IDXGIOutputDuplication* duplication_{};
};

struct DesktopMetadataScratch {
    std::vector<DXGI_OUTDUPL_MOVE_RECT> native_moves;
    std::vector<RECT> native_dirty_rects;
    std::vector<DesktopMoveChange> move_changes;
    std::vector<DesktopChangeRect> dirty_changes;
};

struct DesktopMetadataView {
    DesktopMetadataState state{DesktopMetadataState::unavailable};
    std::span<const DesktopChangeRect> dirty_rects{};
    std::span<const DesktopMoveChange> move_rects{};
};

[[nodiscard]] DesktopChangeRect to_change_rect(const RECT& rect) noexcept {
    return DesktopChangeRect{rect.left, rect.top, rect.right, rect.bottom};
}

[[nodiscard]] DesktopMetadataView query_metadata_changes(
    IDXGIOutputDuplication& duplication, UINT total_metadata_bytes,
    DesktopMetadataScratch& scratch) noexcept {
    scratch.move_changes.clear();
    scratch.dirty_changes.clear();
    if (total_metadata_bytes == 0) return {};

    try {
        const std::size_t move_capacity =
            (total_metadata_bytes + sizeof(DXGI_OUTDUPL_MOVE_RECT) - 1) /
            sizeof(DXGI_OUTDUPL_MOVE_RECT);
        if (scratch.native_moves.size() < move_capacity) {
            scratch.native_moves.resize(move_capacity);
        }
        UINT move_bytes{};
        const HRESULT move_result = duplication.GetFrameMoveRects(
            total_metadata_bytes, scratch.native_moves.data(), &move_bytes);
        if (FAILED(move_result) || move_bytes > total_metadata_bytes ||
            move_bytes % sizeof(DXGI_OUTDUPL_MOVE_RECT) != 0) {
            return {};
        }

        const std::size_t dirty_capacity =
            (total_metadata_bytes + sizeof(RECT) - 1) / sizeof(RECT);
        if (scratch.native_dirty_rects.size() < dirty_capacity) {
            scratch.native_dirty_rects.resize(dirty_capacity);
        }
        UINT dirty_bytes{};
        const HRESULT dirty_result = duplication.GetFrameDirtyRects(
            total_metadata_bytes, scratch.native_dirty_rects.data(), &dirty_bytes);
        if (FAILED(dirty_result) || dirty_bytes > total_metadata_bytes ||
            dirty_bytes % sizeof(RECT) != 0) {
            return {};
        }

        scratch.move_changes.reserve(move_bytes / sizeof(DXGI_OUTDUPL_MOVE_RECT));
        for (std::size_t index = 0; index < move_bytes / sizeof(DXGI_OUTDUPL_MOVE_RECT); ++index) {
            const DXGI_OUTDUPL_MOVE_RECT& move = scratch.native_moves[index];
            const std::int64_t width =
                static_cast<std::int64_t>(move.DestinationRect.right) - move.DestinationRect.left;
            const std::int64_t height =
                static_cast<std::int64_t>(move.DestinationRect.bottom) - move.DestinationRect.top;
            if (width <= 0 || height <= 0) continue;
            scratch.move_changes.push_back(DesktopMoveChange{
                DesktopChangeRect{
                    move.SourcePoint.x,
                    move.SourcePoint.y,
                    static_cast<std::int64_t>(move.SourcePoint.x) + width,
                    static_cast<std::int64_t>(move.SourcePoint.y) + height,
                },
                to_change_rect(move.DestinationRect),
            });
        }

        scratch.dirty_changes.reserve(dirty_bytes / sizeof(RECT));
        for (std::size_t index = 0; index < dirty_bytes / sizeof(RECT); ++index) {
            const RECT& dirty_rect = scratch.native_dirty_rects[index];
            if (dirty_rect.left >= dirty_rect.right || dirty_rect.top >= dirty_rect.bottom) continue;
            scratch.dirty_changes.push_back(to_change_rect(dirty_rect));
        }
        return DesktopMetadataView{
            DesktopMetadataState::reliable,
            scratch.dirty_changes,
            scratch.move_changes,
        };
    } catch (...) {
        // Metadata is an optimization only. Allocation failure must fail open to capture.
    }
    return {};
}
}

struct DxgiDesktopCapture::State {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGIOutputDuplication> duplication;
    ComPtr<ID3D11Texture2D> copy_texture;
    DesktopCaptureRegion requested_region{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint64_t pointer_only_skips{};
    std::uint64_t outside_region_skips{};
    std::uint64_t missed_present_frames{};
    std::uint64_t static_content_repeats{};
    std::uint64_t content_sequence{};
    DesktopMetadataScratch metadata_scratch;
};

DxgiDesktopCapture::DxgiDesktopCapture() noexcept : state_(std::make_unique<State>()) {}
DxgiDesktopCapture::~DxgiDesktopCapture() = default;

CaptureStatus DxgiDesktopCapture::initialize(
    std::uint32_t adapter_index, std::uint32_t output_index,
    DesktopCaptureRegion region) noexcept {
    reset();
    ComPtr<IDXGIFactory1> factory;
    HRESULT result = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(result)) { last_hresult_ = result; return CaptureStatus::initialization_failed; }
    ComPtr<IDXGIAdapter1> adapter;
    result = factory->EnumAdapters1(adapter_index, &adapter);
    if (FAILED(result)) { last_hresult_ = result; return CaptureStatus::initialization_failed; }
    constexpr UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
    const D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    D3D_FEATURE_LEVEL selected{};
    result = D3D11CreateDevice(adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, levels, static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION, &state_->device, &selected, &state_->context);
    if (FAILED(result)) { last_hresult_ = result; return CaptureStatus::initialization_failed; }
    ComPtr<IDXGIOutput> output;
    result = adapter->EnumOutputs(output_index, &output);
    if (FAILED(result)) { last_hresult_ = result; return CaptureStatus::initialization_failed; }
    ComPtr<IDXGIOutput1> output1;
    result = output.As(&output1);
    if (FAILED(result)) { last_hresult_ = result; return CaptureStatus::initialization_failed; }
    result = output1->DuplicateOutput(state_->device.Get(), &state_->duplication);
    if (FAILED(result)) { last_hresult_ = result; return CaptureStatus::initialization_failed; }
    state_->requested_region = region;
    last_hresult_ = S_OK;
    return CaptureStatus::frame_ready;
}

CaptureStatus DxgiDesktopCapture::acquire_next(CapturedDesktopFrame& destination, std::uint32_t timeout_ms) noexcept {
    destination = {};
    if (!state_->duplication) return CaptureStatus::initialization_failed;
    DXGI_OUTDUPL_FRAME_INFO frame_info{};
    ComPtr<IDXGIResource> resource;
    const HRESULT result = state_->duplication->AcquireNextFrame(timeout_ms, &frame_info, &resource);
    if (result == DXGI_ERROR_WAIT_TIMEOUT) {
        last_hresult_ = result;
        return CaptureStatus::timeout;
    }
    if (result == DXGI_ERROR_ACCESS_LOST) {
        // ACCESS_LOST covers display-mode/topology changes and duplication invalidation.
        last_hresult_ = result;
        return CaptureStatus::access_lost;
    }
    if (result == DXGI_ERROR_DEVICE_REMOVED || result == DXGI_ERROR_DEVICE_RESET) {
        last_hresult_ = result;
        return CaptureStatus::device_removed;
    }
    if (FAILED(result)) { last_hresult_ = result; return CaptureStatus::failed; }
    AcquiredFrameGuard acquired_frame(state_->duplication.Get());
    const auto finish = [this, &acquired_frame](CaptureStatus status) noexcept {
        const HRESULT release_result = acquired_frame.release();
        if (FAILED(release_result)) {
            last_hresult_ = release_result;
            return CaptureStatus::failed;
        }
        if (status != CaptureStatus::failed) last_hresult_ = S_OK;
        return status;
    };

    const std::uint64_t last_present_qpc =
        static_cast<std::uint64_t>(frame_info.LastPresentTime.QuadPart);
    if (last_present_qpc == 0) {
        ++state_->pointer_only_skips;
        return finish(CaptureStatus::pointer_only_skipped);
    }
    const std::uint32_t missed_present_frames = missed_present_frame_count(
        last_present_qpc, frame_info.AccumulatedFrames);
    state_->missed_present_frames += missed_present_frames;

    ComPtr<ID3D11Texture2D> source;
    const HRESULT texture_result = resource.As(&source);
    if (FAILED(texture_result)) {
        last_hresult_ = texture_result;
        (void)finish(CaptureStatus::failed);
        return CaptureStatus::failed;
    }
    D3D11_TEXTURE2D_DESC source_description{}; source->GetDesc(&source_description);
    DesktopCaptureRegion region = state_->requested_region;
    if (region.width == 0 || region.height == 0) {
        region = DesktopCaptureRegion{0, 0, source_description.Width, source_description.Height};
    }
    // The requested region is signed so virtual-desktop coordinates cannot wrap.
    // This capture object, however, copies from one selected DXGI output and
    // therefore accepts only non-negative output-local coordinates.
    const std::int64_t region_right =
        static_cast<std::int64_t>(region.x) + region.width;
    const std::int64_t region_bottom =
        static_cast<std::int64_t>(region.y) + region.height;
    if (region.x < 0 || region.y < 0 || region.width == 0U || region.height == 0U ||
        region_right <= region.x || region_bottom <= region.y ||
        region_right > source_description.Width || region_bottom > source_description.Height) {
        last_hresult_ = E_INVALIDARG;
        (void)finish(CaptureStatus::failed);
        return CaptureStatus::failed;
    }
    const auto source_left = static_cast<std::uint32_t>(region.x);
    const auto source_top = static_cast<std::uint32_t>(region.y);
    const auto source_right = static_cast<std::uint32_t>(region_right);
    const auto source_bottom = static_cast<std::uint32_t>(region_bottom);

    const DesktopMetadataView metadata = query_metadata_changes(
        *state_->duplication.Get(), frame_info.TotalMetadataBufferSize,
        state_->metadata_scratch);
    const DesktopFrameSemanticDecision semantic = decide_desktop_frame_semantic(
        DesktopFrameSemanticInput{
            last_present_qpc,
            frame_info.AccumulatedFrames,
            DesktopChangeRect{
                region.x,
                region.y,
                region_right,
                region_bottom,
            },
            metadata.state,
            metadata.dirty_rects,
            metadata.move_rects,
        });
    if (semantic.semantic == DesktopFrameSemantic::outside_region) {
        ++state_->outside_region_skips;
        return finish(CaptureStatus::outside_region_skipped);
    }

    const bool needs_recreate = !state_->copy_texture || state_->width != region.width || state_->height != region.height;
    if (needs_recreate) {
        D3D11_TEXTURE2D_DESC copy_description = source_description;
        copy_description.Width = region.width;
        copy_description.Height = region.height;
        // A desktop-duplication copy is consumed by the D3D11 video processor.
        // Microsoft allows bind flags = 0 for video-processor input views,
        // while SHADER_RESOURCE by itself is not a valid input-view binding.
        copy_description.BindFlags = 0;
        copy_description.CPUAccessFlags = 0;
        copy_description.Usage = D3D11_USAGE_DEFAULT;
        copy_description.MiscFlags = 0;
        const HRESULT create_result = state_->device->CreateTexture2D(&copy_description, nullptr, &state_->copy_texture);
        if (FAILED(create_result)) {
            last_hresult_ = create_result;
            (void)finish(CaptureStatus::failed);
            return CaptureStatus::failed;
        }
        state_->width = region.width; state_->height = region.height;
    }
    const D3D11_BOX source_box{
        source_left, source_top, 0U,
        source_right, source_bottom, 1U,
    };
    state_->context->CopySubresourceRegion(
        state_->copy_texture.Get(), 0, 0, 0, 0, source.Get(), 0, &source_box);
    ++state_->content_sequence;
    if (state_->content_sequence == 0U) ++state_->content_sequence;
    destination = CapturedDesktopFrame{
        state_->copy_texture.Get(),
        state_->width,
        state_->height,
        qpc_now(),
        last_present_qpc,
        frame_info.AccumulatedFrames,
        semantic.missed_present_frames,
        state_->content_sequence,
        false,
    };
    const CaptureStatus status = finish(CaptureStatus::frame_ready);
    if (status != CaptureStatus::frame_ready) destination = {};
    return status;
}

bool DxgiDesktopCapture::repeat_last(
    CapturedDesktopFrame& destination) noexcept {
    destination = {};
    if (!state_->copy_texture || state_->width == 0U || state_->height == 0U) {
        return false;
    }
    const std::uint64_t repeated_at_qpc = qpc_now();
    destination = CapturedDesktopFrame{
        state_->copy_texture.Get(),
        state_->width,
        state_->height,
        repeated_at_qpc,
        repeated_at_qpc,
        0U,
        0U,
        state_->content_sequence,
        true,
    };
    ++state_->static_content_repeats;
    return true;
}

void DxgiDesktopCapture::reset() noexcept {
    state_->copy_texture.Reset(); state_->duplication.Reset(); state_->context.Reset(); state_->device.Reset();
    state_->requested_region = {};
    state_->width = 0; state_->height = 0;
    state_->pointer_only_skips = 0;
    state_->outside_region_skips = 0;
    state_->missed_present_frames = 0;
    state_->static_content_repeats = 0;
    state_->content_sequence = 0;
}

std::int32_t DxgiDesktopCapture::last_hresult() const noexcept { return last_hresult_; }
ID3D11Device* DxgiDesktopCapture::native_device() const noexcept { return state_->device.Get(); }
ID3D11DeviceContext* DxgiDesktopCapture::native_context() const noexcept { return state_->context.Get(); }
DesktopCaptureStatistics DxgiDesktopCapture::statistics_snapshot() const noexcept {
    return DesktopCaptureStatistics{
        state_->pointer_only_skips,
        state_->outside_region_skips,
        state_->missed_present_frames,
        state_->static_content_repeats,
    };
}
}  // namespace vfdual
