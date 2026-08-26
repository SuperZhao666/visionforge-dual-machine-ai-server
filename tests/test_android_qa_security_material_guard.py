from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GRADLE = ROOT / "android_inference_benchmark" / "app" / "build.gradle"


def test_qa_package_requires_formal_authorization_material_preflight() -> None:
    source = GRADLE.read_text(encoding="utf-8")

    task_list = "securityMaterialRequiredPackageTasks = ["
    start = source.index(task_list)
    end = source.index("]", start)
    configured_tasks = source[start:end]

    assert "'packageQa'" in configured_tasks
    assert "'packageOwner'" in configured_tasks
    assert "'packageRelease'" in configured_tasks
    assert "task.dependsOn(" in source[end:]
    assert "tasks.named('verifyDualMachineReleaseSecurityInputs')" in source[end:]
