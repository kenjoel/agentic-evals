import json

from db_agent.tracing import save_trace
import typer
from rich.console import Console
from rich.table import Table

from db_agent.db import initialize_demo_database, test_connection
from db_agent.schema import describe_table, list_tables
from db_agent.tools import list_records
from db_agent.finding_tools import (
    list_open_findings,
    get_finding,
    list_project_findings,
    risk_summary,
)

from db_agent.context_tools import get_finding_context
from db_agent.analyst import answer_question, answer_question_with_trace

app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode=None,
    help="Database agent CLI.",
)
console = Console()


@app.callback()
def main() -> None:
    """Database agent commands."""
    return None


@app.command()
def ping() -> None:
    """Test local database connection."""
    if test_connection():
        console.print("[green]Database connection works.[/green]")


@app.command("init-demo")
def init_demo(
    reset: bool = typer.Option(
        False,
        "--reset",
        help="Drop and recreate the demo database before seeding it.",
    ),
) -> None:
    """Create and seed a local Assurance-style demo database."""
    database_url = initialize_demo_database(reset=reset)
    console.print(f"[green]Demo database ready:[/green] {database_url}")


@app.command()
def tables() -> None:
    """List tables in the configured database."""
    table_names = list_tables()
    if not table_names:
        console.print("[yellow]No tables found in the configured database.[/yellow]")
        return

    console.print("[bold]Tables in the database:[/bold]")
    for table_name in table_names:
        console.print(f" - {table_name}")


@app.command()
def describe(table_name: str) -> None:
    """Describe the columns for one table."""
    columns = describe_table(table_name)

    table = Table(title=f"Schema for table: {table_name}")
    table.add_column("Column", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Nullable", style="green")

    for column in columns:
        table.add_row(column["name"], column["type"], str(column["nullable"]))

    console.print(table)


@app.command()
def records(
    table_name: str,
    limit: int = typer.Option(5, min=1, max=100, help="Maximum number of rows to show."),
) -> None:
    """Show sample records from one allowed table."""
    rows = list_records(table_name, limit=limit)
    if not rows:
        console.print(f"[yellow]No records found in table:[/yellow] {table_name}")
        return

    table = Table(title=f"Records from {table_name}")
    for column_name in rows[0].keys():
        table.add_column(column_name, overflow="fold")

    for row in rows:
        table.add_row(*(str(value) for value in row.values()))

    console.print(table)


@app.command()
def open_findings(
    risk: str | None = None,
    limit: int = 20,
) -> None:
    """
    List open findings, optionally filtered by risk.
    Example: dbagent open-findings --risk high
    """
    rows = list_open_findings(risk_rating=risk, limit=limit)

    if not rows:
        console.print("[yellow]No matching open findings found.[/yellow]")
        return

    table = Table(title="Open Findings")
    table.add_column("ID")
    table.add_column("Project")
    table.add_column("Assessable")
    table.add_column("Risk")
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Created")

    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["project_id"]),
            str(row["assessable_id"]),
            row["risk_rating"],
            row["status"],
            row["title"],
            row["created_at"],
        )

    console.print(table)


@app.command()
def finding(finding_id: int) -> None:
    """
    Get one finding by ID.
    Example: dbagent finding 2
    """
    row = get_finding(finding_id)

    if not row:
        console.print(f"[yellow]No finding found with ID {finding_id}.[/yellow]")
        return

    console.print_json(json.dumps(row, default=str))


@app.command()
def project_findings(
    project_id: int,
    status: str | None = None,
    limit: int = 50,
):
    """
    List findings for one project.
    Example: dbagent project-findings 1 --status open
    """
    rows = list_project_findings(
        project_id=project_id,
        status=status,
        limit=limit,
    )

    if not rows:
        console.print("[yellow]No matching findings found.[/yellow]")
        return

    table = Table(title=f"Findings for Project {project_id}")
    table.add_column("ID")
    table.add_column("Risk")
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Created")

    for row in rows:
        table.add_row(
            str(row["id"]),
            row["risk_rating"],
            row["status"],
            row["title"],
            row["created_at"],
        )

    console.print(table)


@app.command()
def summary() -> None:
    """
    Show finding counts by risk and status.
    Example: dbagent summary
    """
    rows = risk_summary()

    table = Table(title="Finding Risk Summary")
    table.add_column("Risk")
    table.add_column("Status")
    table.add_column("Count")

    for row in rows:
        table.add_row(
            row["risk_rating"],
            row["status"],
            str(row["count"]),
        )

    console.print(table)


@app.command()
def finding_context(finding_id: int) -> None:
    """
    Get a finding with project and assessable context.
    Example: dbagent finding-context 2
    """
    row = get_finding_context(finding_id)

    if not row:
        console.print(f"[yellow]No finding context found for ID {finding_id}.[/yellow]")
        return

    console.print_json(json.dumps(row, default=str))



@app.command()
def ask(
    question: str,
    trace: bool = False,
):
    """
    Ask the local database analyst a question.
    Example: dbagent ask "show me open critical findings"
    Example with trace: dbagent ask "explain finding 9001" --trace
    """
    if trace:
        answer, tool_trace = answer_question_with_trace(question)
        path = save_trace(tool_trace)
        console.print(answer)
        console.print(f"\n[dim]Trace written to {path}[/dim]")
        return

    answer = answer_question(question)
    console.print(answer)


if __name__ == "__main__":
    app()


