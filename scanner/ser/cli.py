from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from scanner.ser.models import SessionSource
from scanner.ser.parsing import merge_cli_session, parse_cookie_flag, parse_header_flag
from scanner.ser.phases.controlled_validation import ApprovalRequiredError, run_controlled_validation
from scanner.ser.phases.web_crawl import crawl_web
from scanner.ser.phases.web_interact import web_interact
from scanner.ser.scope_guard import same_origin_prefix

ser_app = typer.Typer(help="SER - authenticated session tools (authorized use only).")


@ser_app.command("session-audit")
def session_audit(
    cookie: Annotated[list[str] | None, typer.Option("--cookie", help='Repeatable: name=value')] = None,
    header: Annotated[list[str] | None, typer.Option('--header', help='Repeatable: "Name: value"')] = None,
    bearer_token_env: Annotated[
        str | None, typer.Option("--bearer-token-env", help="Environment variable name for bearer token")
    ] = None,
    session_file: Annotated[Path | None, typer.Option("--session-file", help="JSON or YAML session file")] = None,
    scope_url: Annotated[
        str | None,
        typer.Option("--scope-url", help="Restrict requests to this origin prefix (scheme://host[:port])"),
    ] = None,
) -> None:
    """Print redacted session summary only (never prints raw secrets)."""

    cookies = parse_cookie_flag(cookie)
    headers = parse_header_flag(header)
    prefixes: tuple[str, ...] = ()
    if scope_url:
        prefixes = (same_origin_prefix(scope_url),)
    sess = merge_cli_session(
        cookies=cookies,
        headers=headers,
        bearer_token_env_name=bearer_token_env,
        session_file=session_file,
        source=SessionSource.MERGED,
        allowed_prefixes=prefixes,
    )
    typer.echo(json.dumps(sess.model_for_audit(), indent=2))


@ser_app.command("crawl")
def crawl_cmd(
    url: str = typer.Argument(..., help="Starting URL (must match scope when set)."),
    cookie: Annotated[list[str] | None, typer.Option("--cookie")] = None,
    header: Annotated[list[str] | None, typer.Option("--header")] = None,
    bearer_token_env: Annotated[str | None, typer.Option("--bearer-token-env")] = None,
    session_file: Annotated[Path | None, typer.Option("--session-file")] = None,
    max_pages: int = typer.Option(5, "--max-pages"),
) -> None:
    prefixes = (same_origin_prefix(url),)
    sess = merge_cli_session(
        cookies=parse_cookie_flag(cookie),
        headers=parse_header_flag(header),
        bearer_token_env_name=bearer_token_env,
        session_file=session_file,
        allowed_prefixes=prefixes,
    )
    out = crawl_web(url, sess, max_pages=max_pages)
    typer.echo(json.dumps(out, indent=2, default=str))


@ser_app.command("interact")
def interact_cmd(
    url: str = typer.Argument(...),
    cookie: Annotated[list[str] | None, typer.Option("--cookie")] = None,
    header: Annotated[list[str] | None, typer.Option("--header")] = None,
    bearer_token_env: Annotated[str | None, typer.Option("--bearer-token-env")] = None,
    session_file: Annotated[Path | None, typer.Option("--session-file")] = None,
) -> None:
    prefixes = (same_origin_prefix(url),)
    sess = merge_cli_session(
        cookies=parse_cookie_flag(cookie),
        headers=parse_header_flag(header),
        bearer_token_env_name=bearer_token_env,
        session_file=session_file,
        allowed_prefixes=prefixes,
    )
    out = web_interact(url, sess)
    typer.echo(json.dumps(out, indent=2, default=str))


@ser_app.command("validate")
def validate_cmd(
    url: str = typer.Argument(...),
    approved: bool = typer.Option(
        False,
        "--approved",
        help="Required: explicit operator approval for controlled validation.",
    ),
    cookie: Annotated[list[str] | None, typer.Option("--cookie")] = None,
    header: Annotated[list[str] | None, typer.Option("--header")] = None,
    bearer_token_env: Annotated[str | None, typer.Option("--bearer-token-env")] = None,
    session_file: Annotated[Path | None, typer.Option("--session-file")] = None,
) -> None:
    prefixes = (same_origin_prefix(url),)
    sess = merge_cli_session(
        cookies=parse_cookie_flag(cookie),
        headers=parse_header_flag(header),
        bearer_token_env_name=bearer_token_env,
        session_file=session_file,
        allowed_prefixes=prefixes,
    )
    try:
        out = run_controlled_validation(url, sess, approved=approved)
    except ApprovalRequiredError as exc:
        typer.secho(str(exc), err=True, fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(out, indent=2, default=str))
