from pathlib import Path
from fastapi.templating import Jinja2Templates

_tpl_dir = Path(__file__).resolve().parent / "templates"


def _security_context(request):
    return {"csrf_token": str(getattr(request.state, "csrf_token", "") or "")}


templates = Jinja2Templates(directory=str(_tpl_dir), context_processors=[_security_context])
