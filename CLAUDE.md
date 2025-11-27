# Claude Code Working Conventions

This file contains instructions and conventions for Claude Code when working on this project.

## Git Commit Convention

**IMPORTANT**: Create a git commit after EVERY prompt/response interaction, even when files haven't changed.

### Commit Requirements

1. **Always commit after each exchange** - Use `--allow-empty` flag when no files changed
2. **Include full user prompt** in commit message under "USER PROMPT:" section
3. **Include complete assistant response** under "ASSISTANT RESPONSE:" section (excluding code diffs)
4. **Use descriptive subject line** following conventional commit format
5. **Target file**: Always include `MCP_ZEEK_SPECIFICATION.md` in commit command

### Commit Message Template

```
Docs: <Brief description of the exchange>

USER PROMPT:
============
<Full user prompt text>

ASSISTANT RESPONSE:
===================
<Summary of assistant response, key decisions, actions taken>
<Exclude code diffs - those are in the commit itself>
```

### Example Commands

```bash
# When files changed:
git commit -m "$(cat <<'EOF'
Docs: <description>

USER PROMPT:
============
<prompt>

ASSISTANT RESPONSE:
===================
<response>
EOF
)" MCP_ZEEK_SPECIFICATION.md

# When no files changed:
git commit --allow-empty -m "$(cat <<'EOF'
Docs: <description>

USER PROMPT:
============
<prompt>

ASSISTANT RESPONSE:
===================
<response>
EOF
)" MCP_ZEEK_SPECIFICATION.md
```

## Project Context

### Primary Objective
Adding MCP (Model Context Protocol) support to Zeek network security monitoring framework.

### Key Technical Approach
1. **Phase 1**: Convert existing C++ HTTP protocol analyzer to Spicy parser framework
2. **Phase 2**: Implement MCP protocol support on top of Spicy HTTP parser
3. **Focus areas**:
   - Performance optimization for high-visibility deployments (TLSI proxies, TLS termination)
   - Security hardening (compression bombs, DoS protection)
   - Privacy-aware logging with configurable content capture
   - Combined request/response logging (following Zeek HTTP conventions)

### Key Files
- `MCP_ZEEK_SPECIFICATION.md` - Main specification document (current version: 1.2)
- `MCP_ZEEK_SPECIFICATION_ORIGINAL.md` - Backup of original separate-logging approach

### Important Design Decisions
- **Combined logging**: Request and response in single log entry (like HTTP analyzer)
- **Optional content capture**: Disabled by default, configurable for debugging
- **C++ decompression plugin**: Required for performance in high-volume scenarios
- **Performance first**: Early detection, selective parsing, security hardening

## Working Style Preferences

- **Be concise** - User prefers direct technical communication
- **Track decisions** - Use git commits as audit trail of reasoning
- **Performance matters** - User emphasized optimization for production deployments
- **Security hardening** - Consider attack scenarios (compression bombs, etc.)
- **Follow Zeek conventions** - Study existing analyzers before proposing new patterns

## Session Continuity

This file ensures that important working conventions persist across Claude Code sessions. When starting a new session, Claude should read this file to understand:
1. How to structure git commits
2. Project goals and technical approach
3. Key design decisions already made
4. Preferred working style
