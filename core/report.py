from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

TEMPLATE_DIR = Path(__file__).parent / "templates"
OUTPUT_DIR = Path("outputs")
ENV = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

def _gather_results(target: str) -> dict[str, str]:
    """Read every txt file for the target and return {section: content}."""
    results: dict[str, str] = {}
    for f in sorted(OUTPUT_DIR.glob(f"{target}_*.txt")):
        section = f.stem.replace(f"{target}_", "")  # Changed from f.name to f.stem
        results[section] = f.read_text(encoding="utf-8")  # Added encoding
    return results

def build_report(target: str) -> Path:
    """Render HTML with Jinja2, convert to PDF, return PDF path."""
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    data = _gather_results(target)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")  # Fixed en-dash to regular dash
    template = ENV.get_template("master_report.html")
    html_text = template.render(target=target, ts=timestamp, results=data)

    html_path = OUTPUT_DIR / f"{target}_report.html"
    pdf_path = OUTPUT_DIR / f"{target}_report.pdf"

    html_path.write_text(html_text, encoding="utf-8")  # Fixed en-dash to regular dash
    HTML(string=html_text).write_pdf(pdf_path)

    print(f"[report] ✔ HTML → {html_path}")
    print(f"[report] ✔ PDF → {pdf_path}")
    return pdf_path  # Removed unnecessary 'and' condition