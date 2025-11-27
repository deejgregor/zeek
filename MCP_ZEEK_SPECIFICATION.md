# Zeek MCP Protocol Support: Specification and Implementation Plan

**Version:** 1.3
**Date:** November 26, 2025
**Author:** Zeek Development Team
**Document Type:** Planning Document for Zeek MCP Integration

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Background](#background)
3. [Current State Analysis](#current-state-analysis)
4. [MCP Protocol Overview](#mcp-protocol-overview)
5. [Gap Analysis](#gap-analysis)
6. [Proposed Zeek Log Format for MCP](#proposed-zeek-log-format-for-mcp)
7. [HTTP to Spicy Migration Plan](#http-to-spicy-migration-plan)
8. [MCP Protocol Implementation Plan](#mcp-protocol-implementation-plan)
9. [Testing Strategy](#testing-strategy)
10. [Timeline and Milestones](#timeline-and-milestones)
11. [AI-Assisted Development Estimates](#ai-assisted-development-estimates)
12. [References](#references)

---

## Version History

- **v1.3** (2025-11-26): Added AI-assisted development estimates including token budgets, human time, wall clock time, detailed breakdowns, session planning, and cost analysis
- **v1.2** (2025-11-26): Updated terminology from "B&I proxies" to "TLSI/TLS termination" to cover broader deployment scenarios
- **v1.1** (2025-11-26): Added optional content capture fields and comprehensive privacy/security guidance
- **v1.0** (2025-11-26): Initial specification with combined request/response logging, performance optimization, and complete implementation plan

---

## Executive Summary

This document outlines a comprehensive plan to add Model Context Protocol (MCP) support to Zeek, a powerful network security monitoring framework. The implementation requires:

1. **HTTP Modernization:** Migrate the existing C++ HTTP protocol analyzer to Spicy parser framework
2. **Enhanced HTTP Support:** Ensure robust handling of Server-Sent Events (SSE) and streaming HTTP features
3. **MCP Protocol Layer:** Build a new protocol analyzer specifically for MCP over HTTP
4. **Logging Infrastructure:** Design appropriate Zeek log formats for MCP traffic analysis

This phased approach ensures backward compatibility while enabling modern protocol analysis capabilities.

---

## Background

### What is Zeek?

Zeek (formerly Bro) is a powerful open-source network security monitoring framework that provides:
- Deep packet inspection and protocol analysis
- Rich logging of network activity
- Scriptable event-driven analysis
- Support for numerous application-layer protocols

### What is MCP?

The Model Context Protocol (MCP) is an open standard introduced by Anthropic in November 2024 that:
- Standardizes how AI systems integrate with external data sources
- Uses JSON-RPC 2.0 for message encoding
- Supports multiple transport mechanisms (HTTP/SSE, stdio, etc.)
- Enables AI assistants to access tools, resources, and prompts

### Why MCP Support in Zeek?

As AI systems become increasingly integrated into enterprise environments, network security teams need visibility into:
- MCP traffic patterns and data flows
- AI assistant interactions with enterprise systems
- Potential security risks from AI tool invocations
- Compliance and audit trails for AI-mediated access

---

## Current State Analysis

### Zeek Architecture

Zeek's architecture consists of:

```
┌──────────────────────────────────────────────┐
│            Zeek Script Layer                 │
│   (Event handlers, logging, policies)        │
└──────────────────────────────────────────────┘
                     ▲
                     │ Events
                     │
┌──────────────────────────────────────────────┐
│         Protocol Analyzers Layer             │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│   │   HTTP   │  │   DNS    │  │   SSL    │   │
│   │ (C/C++)  │  │ (C/C++)  │  │ (Spicy)  │   │
│   └──────────┘  └──────────┘  └──────────┘   │
└──────────────────────────────────────────────┘
                     ▲
                     │
┌──────────────────────────────────────────────┐
│        Packet Analysis & TCP Reassembly      │
└──────────────────────────────────────────────┘
```

### Current HTTP Implementation

**Location:** `src/analyzer/protocol/http/`

**Key Components:**
- **HTTP.h/HTTP.cc:** Main analyzer (1,700+ lines of C++)
- **HTTP_Entity:** Handles message bodies with MIME parsing
- **HTTP_Message:** Manages request/response pairs
- **Chunked Transfer Support:** Already implemented (lines 18-26, HTTP.h)
- **Content Encoding:** Supports gzip, deflate (lines 179-192, HTTP.cc)

**Key Features:**
- HTTP/0.9, HTTP/1.0, HTTP/1.1 support
- Connection management (keep-alive, pipelining)
- MIME multipart parsing
- File extraction integration
- WebSocket upgrade detection
- CONNECT method proxy support

**Chunked Transfer State Machine (HTTP.h:18-26):**
```cpp
enum CHUNKED_TRANSFER_STATE : uint8_t {
    NON_CHUNKED_TRANSFER,
    BEFORE_CHUNK,
    EXPECT_CHUNK_SIZE,
    EXPECT_CHUNK_DATA,
    EXPECT_CHUNK_DATA_CRLF,
    EXPECT_CHUNK_TRAILER,
    EXPECT_NOTHING,
};
```

**Implementation (HTTP.cc:109-147):**
- Parses chunk size in hexadecimal
- Handles chunk data delivery
- Supports trailing headers
- Integrates with content delivery pipeline

### Current HTTP Logging

**Log File:** `http.log`

**Key Fields (from scripts/base/protocols/http/main.zeek:28-89):**
```zeek
type Info: record {
    ts: time                    # Timestamp
    uid: string                 # Connection UID
    id: conn_id                 # 4-tuple
    trans_depth: count          # Pipeline depth
    method: string              # GET, POST, etc.
    host: string                # Host header
    uri: string                 # Request URI
    referrer: string            # Referer header
    version: string             # HTTP version
    user_agent: string          # User-Agent
    origin: string              # Origin header
    request_body_len: count     # Request size
    response_body_len: count    # Response size
    status_code: count          # HTTP status
    status_msg: string          # Status message
    info_code: count            # 1xx codes
    info_msg: string            # 1xx messages
    username: string            # Basic auth
    password: string            # Basic auth
    proxied: set[string]        # Proxy headers
    range_request: bool         # 206 support
};
```

### Spicy Parser Framework

**Location:** `src/spicy/`

**What is Spicy?**
Spicy is a domain-specific language for writing protocol parsers that:
- Generates efficient C++ code
- Integrates seamlessly with Zeek
- Provides grammar-based protocol definitions
- Eliminates manual C++ analyzer writing

**Example Spicy Analyzers in Zeek:**
- QUIC (modern)
- WebSocket (modern)
- LDAP (migrated)
- PostgreSQL (migrated)

**Spicy Integration Pattern:**
1. `.spicy` file defines grammar
2. `.evt` file maps to Zeek events
3. Spicy compiler generates C++
4. Zeek loads analyzer as plugin

### Testing Infrastructure

**Framework:** btest (behavior testing)

**Location:** `testing/btest/`

**HTTP Tests:** 45+ test cases covering:
- Basic GET/POST requests
- Chunked transfer encoding
- Content-Range (206 responses)
- HTTP/0.9, HTTP/1.0, HTTP/1.1
- WebSocket upgrades
- CONNECT proxying
- Pipeline handling
- Entity gaps
- Various edge cases

**Test Structure:**
```
testing/btest/scripts/base/protocols/http/
├── http-pipelining.zeek
├── http-connect.zeek
├── entity-gap.zeek
├── content-range-gap.zeek
└── ... (40+ more)

testing/btest/Baseline/
└── scripts.base.protocols.http.*/
    ├── http.log
    ├── conn.log
    └── other.log
```

---

## MCP Protocol Overview

### MCP Architecture

MCP defines a client-server architecture for AI system integration:

```
┌─────────────────┐       JSON-RPC over       ┌─────────────────┐
│   MCP Client    │◄─────── HTTP/SSE ────────►│   MCP Server    │
│  (AI Assistant) │                           │ (Data Source)   │
└─────────────────┘                           └─────────────────┘
        │                                               │
        │                                               │
        ▼                                               ▼
  ┌──────────┐                                  ┌──────────────┐
  │ Prompts  │                                  │  Resources   │
  │ Tools    │                                  │  Tools       │
  │ Sampling │                                  │  Prompts     │
  └──────────┘                                  └──────────────┘
```

### Transport Layer

**Current Standard: Streamable HTTP (2025-03-26)**

**Deprecated: HTTP + SSE (pre-2025-03-26)**

#### Streamable HTTP Details

**Server Requirements:**
- Single HTTP endpoint supporting POST and GET
- POST: Accept JSON-RPC messages
- Response: Either `application/json` OR `text/event-stream`

**Client Requirements:**
- Use HTTP POST for sending messages
- Include `Accept: application/json, text/event-stream`
- Body: Single JSON-RPC request/notification/response

**Server-Sent Events (SSE) Streaming:**
- Used for streaming multiple server responses
- Content-Type: `text/event-stream`
- Events contain JSON-RPC messages
- Support event IDs for resumption
- Client uses `Last-Event-ID` header to resume

**Connection Resumption:**
- Optional server feature
- Server attaches unique `id` to SSE events
- Client sends GET with `Last-Event-ID` header
- Server replays from that point

#### HTTP + SSE (Legacy/Deprecated)

**Dual-Endpoint Architecture:**
- **SSE Endpoint:** Server→Client streaming
- **Message Endpoint:** Client→Server messaging

**Flow:**
1. Client connects to SSE endpoint
2. Server sends `endpoint` event with message URI
3. Client POSTs messages to that URI
4. Server streams responses via SSE

### Message Format

**JSON-RPC 2.0**

**Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "get_weather",
        "arguments": {"city": "San Francisco"}
    }
}
```

**Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "The weather is sunny, 72°F"
            }
        ]
    }
}
```

**Notification (no response expected):**
```json
{
    "jsonrpc": "2.0",
    "method": "notifications/progress",
    "params": {
        "progressToken": "abc123",
        "progress": 50,
        "total": 100
    }
}
```

### MCP Core Primitives

#### 1. Resources
Structured data for LLM context (similar to RAG):
- File contents
- Database records
- API responses
- Document chunks

#### 2. Tools
Functions the LLM can invoke:
- Search databases
- Execute code
- Make API calls
- File operations

#### 3. Prompts
Predefined templates/instructions:
- System prompts
- Few-shot examples
- Task templates

#### 4. Sampling
Client capability to request LLM completions

#### 5. Roots
Client-defined context boundaries

### Key MCP Methods

**Server Capabilities:**
- `initialize` - Handshake
- `resources/list` - Available resources
- `resources/read` - Fetch resource
- `tools/list` - Available tools
- `tools/call` - Execute tool
- `prompts/list` - Available prompts
- `prompts/get` - Fetch prompt

**Client Capabilities:**
- `sampling/createMessage` - Request completion

---

## Gap Analysis

### HTTP Protocol Gaps

Based on analysis of current HTTP analyzer (src/analyzer/protocol/http/HTTP.cc) vs. MCP requirements:

#### ✅ Already Supported

1. **Chunked Transfer Encoding**
   - Full state machine (lines 109-147, HTTP.cc)
   - Chunk size parsing (hexadecimal)
   - Trailing headers support
   - **Status:** Production-ready

2. **Content Encoding**
   - gzip decompression (lines 179-192)
   - deflate support
   - **Status:** Production-ready

3. **HTTP/1.1 Features**
   - Keep-alive connections
   - Pipelining (with depth tracking)
   - Connection upgrade mechanism
   - **Status:** Production-ready

4. **Request/Response Tracking**
   - Pipelined request queue
   - Response matching
   - Transaction depth
   - **Status:** Production-ready

#### ⚠️ Needs Enhancement

1. **Server-Sent Events (SSE) Parsing**
   - **Current:** HTTP treats SSE as generic response body
   - **Needed:** Parse SSE event stream format
   - **Gap:** No awareness of:
     - `event:` field
     - `data:` field
     - `id:` field
     - `retry:` field
   - **Impact:** Cannot track individual SSE events or connection resumption

2. **Bidirectional HTTP Streams**
   - **Current:** Assumes request→response pattern
   - **Needed:** Handle concurrent request/response streams
   - **Gap:** Streamable HTTP allows responses before request completes
   - **Impact:** May mis-order events in logs

3. **POST Request Body Parsing**
   - **Current:** Treats body as opaque blob
   - **Needed:** JSON parsing for JSON-RPC detection
   - **Gap:** No content-type-aware parsing
   - **Impact:** Cannot extract MCP method names without deep parsing

### Spicy Migration Gaps

**Current Situation:**
- HTTP analyzer is pure C++ (~1,700 lines)
- No existing HTTP Spicy grammar
- Chunked encoding in Spicy not widely demonstrated

**Migration Challenges:**

1. **Grammar Complexity**
   - HTTP header parsing (RFC 7230)
   - MIME multipart boundaries
   - Chunked encoding state machine
   - WebSocket upgrade detection

2. **State Management**
   - Request/response correlation
   - Pipeline tracking
   - Connection-level state (keep-alive)

3. **Performance**
   - Current C++ analyzer highly optimized
   - Spicy-generated code must match performance
   - High-volume HTTP traffic in production

4. **Feature Parity**
   - All 45+ test cases must pass
   - File extraction hooks
   - Content decompression
   - Weird detection

### MCP-Specific Gaps

**What Doesn't Exist:**

1. **MCP Protocol Analyzer**
   - No Spicy grammar for MCP
   - No JSON-RPC message parser
   - No event definitions

2. **MCP Event Generation**
   - No events for tools/call
   - No events for resources/read
   - No events for sampling requests

3. **MCP Logging**
   - No mcp.log format
   - No JSON-RPC correlation

4. **SSE Event Stream Parser**
   - No SSE grammar in Spicy
   - No SSE event extraction

---

## Proposed Zeek Log Format for MCP

### Design Principles

1. **Correlation:** Link MCP transactions to HTTP connections
2. **Visibility:** Capture security-relevant MCP operations
3. **Efficiency:** Avoid excessive log volume
4. **Compatibility:** Follow Zeek logging conventions

### Log File: mcp.log

**Purpose:** Track MCP protocol interactions at the JSON-RPC level

**Design Decision: Request/Response Correlation**

Following Zeek's HTTP logging pattern, MCP uses **combined request/response logging** where a single log entry represents a complete transaction. This approach:
- Mirrors HTTP's design (request method + response status in one record)
- Simplifies analysis (no need to join separate log files)
- Handles pipelining naturally (like HTTP's `trans_depth`)
- Works well with JSON-RPC's request/response ID matching

**Alternative Considered:** Separate request and response log entries correlated by `msg_id`. This was rejected because:
- Increases log volume (2x entries per transaction)
- Requires post-processing to correlate request/response pairs
- Doesn't handle notifications (no response) well
- Diverges from Zeek conventions

**How Correlation Works:**

1. **Requests with Responses:** Request fields populated immediately, response fields filled when response arrives, then logged
2. **Notifications:** No response expected, logged immediately with response fields unset
3. **Multiple Responses (SSE):** First response completes the log entry, subsequent responses logged as separate entries with same `parent_msg_id`
4. **Orphaned Requests:** If response never arrives (connection closed), logged with `timed_out=T`

**Schema:**

```zeek
module MCP;

export {
    redef enum Log::ID += { LOG };

    ## Content capture settings for detailed MCP analysis
    ## WARNING: Enabling these may log sensitive data

    ## Capture full prompt content from prompts/get responses
    option capture_prompt_content = F;

    ## Capture resource content previews from resources/read responses
    option capture_resource_preview = F;

    ## Capture full sampling prompts sent to LLMs
    option capture_sampling_prompts = F;

    ## Maximum size for captured content fields (0 = unlimited)
    option max_content_capture_size = 1024;

    ## Apply content redaction patterns (e.g., for credit cards, SSNs)
    option enable_content_redaction = T;

    type MethodType: enum {
        INITIALIZE,
        RESOURCES_LIST,
        RESOURCES_READ,
        TOOLS_LIST,
        TOOLS_CALL,
        PROMPTS_LIST,
        PROMPTS_GET,
        SAMPLING_CREATE_MESSAGE,
        COMPLETION_COMPLETE,
        ROOTS_LIST,
        NOTIFICATIONS_PROGRESS,
        NOTIFICATIONS_MESSAGE,
        PING,
        OTHER,
    };

    type Info: record {
        ## Timestamp when request was sent
        ts: time &log;

        ## Connection UID from HTTP
        uid: string &log;

        ## Connection 4-tuple
        id: conn_id &log;

        ## Transaction depth (for pipelining/parallel requests)
        trans_depth: count &log &default=0;

        ## JSON-RPC version (should be "2.0")
        jsonrpc_version: string &log &optional;

        ## JSON-RPC message ID (for correlation)
        msg_id: count &log &optional;

        ## --- REQUEST FIELDS ---

        ## MCP method category
        method: MethodType &log &optional;

        ## Full method name (e.g., "tools/call")
        method_name: string &log &optional;

        ## For tool calls: tool name
        tool_name: string &log &optional;

        ## For tool calls: argument summary (truncated)
        tool_args: string &log &optional;

        ## For resource reads: resource URI
        resource_uri: string &log &optional;

        ## For prompts: prompt name
        prompt_name: string &log &optional;

        ## For prompts: prompt description (if provided by server)
        prompt_description: string &log &optional;

        ## For prompts: full prompt content (optional, see capture settings)
        prompt_content: string &log &optional;

        ## For resource reads: content preview (optional, truncated)
        resource_content_preview: string &log &optional;

        ## For resource reads: content size (bytes)
        resource_content_size: count &log &optional;

        ## For sampling: model name
        model: string &log &optional;

        ## For sampling: prompt content sent to LLM (optional, see capture settings)
        sampling_prompt: string &log &optional;

        ## Request message size (bytes)
        request_size: count &log &default=0;

        ## --- RESPONSE FIELDS ---

        ## Whether this was a notification (no response expected)
        is_notification: bool &log &default=F;

        ## Whether response was received
        has_response: bool &log &default=F;

        ## Response status: "success", "error", or "timeout"
        response_status: string &log &optional;

        ## For errors: error code
        error_code: int &log &optional;

        ## For errors: error message (truncated)
        error_message: string &log &optional;

        ## Response message size (bytes)
        response_size: count &log &default=0;

        ## Time from request to response
        response_time: interval &log &optional;

        ## SSE event ID (if response came via SSE)
        sse_event_id: string &log &optional;

        ## --- SPECIAL CASES ---

        ## For SSE streams with multiple responses: ID of first message
        parent_msg_id: count &log &optional;

        ## Whether this request timed out (no response before connection close)
        timed_out: bool &log &default=F;

        ## Progressive notification token (for progress updates)
        progress_token: string &log &optional;

        ## Progress value (for progress notifications)
        progress_value: count &log &optional;
        progress_total: count &log &optional;
    };

    ## State tracking for request/response correlation
    type State: record {
        ## Pending requests awaiting responses
        pending: table[count] of Info;
        ## Transaction depth counter
        trans_depth: count &default=0;
    };
}
```

### Log File: mcp_sse.log

**Purpose:** Track Server-Sent Events stream metadata

**Schema:**

```zeek
module MCP;

export {
    redef enum Log::ID += { SSE_LOG };

    type SSEInfo: record {
        ## Timestamp when SSE stream started
        ts: time &log;

        ## Connection UID
        uid: string &log;

        ## Connection 4-tuple
        id: conn_id &log;

        ## SSE connection initiated by client (orig) or server (resp)
        is_orig: bool &log;

        ## Total number of events in stream
        event_count: count &log &default=0;

        ## Last event ID seen (for resumption tracking)
        last_event_id: string &log &optional;

        ## Stream duration
        duration: interval &log &optional;

        ## Whether stream closed cleanly
        clean_close: bool &log &default=F;

        ## Total bytes transferred in SSE stream
        total_bytes: count &log &default=0;

        ## Reconnection attempts (based on Last-Event-ID)
        reconnect_count: count &log &default=0;
    };
}
```

### Enhanced http.log Fields

**Additions to existing HTTP::Info:**

```zeek
## In scripts/base/protocols/http/main.zeek

type Info: record {
    # ... existing fields ...

    ## Indicates this HTTP connection carries MCP traffic
    is_mcp: bool &log &optional;

    ## MCP endpoint path (e.g., "/mcp/v1")
    mcp_endpoint: string &log &optional;

    ## Number of SSE events (for text/event-stream responses)
    sse_event_count: count &log &optional;

    ## SSE connection resumption detected
    sse_resumed: bool &log &optional;
};
```

### Example Log Entries

**mcp.log - Successful Tool Invocation (Request + Response):**
```
ts=1732600000.123456 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=1 jsonrpc_version=2.0 msg_id=42 method=TOOLS_CALL method_name=tools/call
tool_name=execute_query tool_args={"database":"production","query":"SELECT..."}[truncated]
request_size=1024 is_notification=F has_response=T response_status=success
response_size=2048 response_time=0.333s sse_event_id=evt-12345 timed_out=F
```

**mcp.log - Prompt Usage (with optional content capture):**
```
ts=1732600000.300000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=2 jsonrpc_version=2.0 msg_id=50 method=PROMPTS_GET method_name=prompts/get
prompt_name=git-commit prompt_description="Generate a git commit message"
tool_args={"changes":"Added MCP support to HTTP analyzer"}[truncated]
prompt_content={"messages":[{"role":"user","content":"Generate a commit..."}]}[truncated]
request_size=512 is_notification=F has_response=T response_status=success
response_size=256 response_time=0.100s timed_out=F
```
*Note: `prompt_content` only present if `capture_prompt_content=T`*

**mcp.log - Resource Read (with optional preview):**
```
ts=1732600000.600000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=3 jsonrpc_version=2.0 msg_id=51 method=RESOURCES_READ
method_name=resources/read resource_uri=file:///project/config.yaml
resource_content_preview="# Application Config\nserver:\n  host: localhost..."[truncated]
resource_content_size=8192 request_size=256 is_notification=F has_response=T
response_status=success response_size=8500 response_time=0.050s timed_out=F
```
*Note: `resource_content_preview` only present if `capture_resource_preview=T`*

**mcp.log - Notification (No Response):**
```
ts=1732600000.500000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=4 jsonrpc_version=2.0 method=NOTIFICATIONS_PROGRESS
method_name=notifications/progress request_size=256 is_notification=T has_response=F
progress_token=task-abc123 progress_value=50 progress_total=100 timed_out=F
```

**mcp.log - Error Response:**
```
ts=1732600000.750000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=5 jsonrpc_version=2.0 msg_id=43 method=RESOURCES_READ
method_name=resources/read resource_uri=file:///etc/passwd request_size=512
is_notification=F has_response=T response_status=error error_code=-32001
error_message="Access denied to resource" response_size=128 response_time=0.050s timed_out=F
```

**mcp.log - Sampling Request (metadata only, no prompt content):**
```
ts=1732600000.900000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=6 jsonrpc_version=2.0 msg_id=52 method=SAMPLING_CREATE_MESSAGE
method_name=sampling/createMessage model=claude-3-5-sonnet-20241022
request_size=4096 is_notification=F has_response=T response_status=success
response_size=2048 response_time=1.250s timed_out=F
```
*Note: `sampling_prompt` field omitted (default: `capture_sampling_prompts=F`)*

**mcp.log - Timed Out (No Response Received):**
```
ts=1732600001.000000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=4 jsonrpc_version=2.0 msg_id=44 method=TOOLS_CALL
method_name=tools/call tool_name=slow_operation request_size=2048 is_notification=F
has_response=F timed_out=T
```

**mcp.log - Multiple SSE Responses (Streaming):**
```
# First response (completes the transaction)
ts=1732600002.000000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=5 jsonrpc_version=2.0 msg_id=45 method=SAMPLING_CREATE_MESSAGE
method_name=sampling/createMessage model=claude-3-5-sonnet request_size=4096
is_notification=F has_response=T response_status=success response_size=1024
response_time=0.200s sse_event_id=evt-20001 timed_out=F

# Subsequent streaming responses (linked via parent_msg_id)
ts=1732600002.100000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=6 jsonrpc_version=2.0 parent_msg_id=45 response_status=success
response_size=512 sse_event_id=evt-20002

ts=1732600002.150000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=7 jsonrpc_version=2.0 parent_msg_id=45 response_status=success
response_size=512 sse_event_id=evt-20003
```

**mcp_sse.log:**
```
ts=1732600000.000000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
is_orig=F event_count=15 last_event_id=evt-12345 duration=10.5s
clean_close=T total_bytes=32768 reconnect_count=0
```

### Implementation Details: Request/Response Correlation

**Connection-Level State Tracking:**

Similar to HTTP's approach (see `scripts/base/protocols/http/main.zeek:93-104`), MCP maintains state per connection:

```zeek
# Added to connection record
redef record connection += {
    mcp: MCP::Info &optional;
    mcp_state: MCP::State &optional;
};
```

**Event Handler Flow:**

```zeek
# When request is seen
event mcp_json_rpc_message(c: connection, is_orig: bool, data: string)
{
    local msg = parse_json(data);

    if ( msg?$method ) {
        # This is a REQUEST or NOTIFICATION
        if ( ! c?$mcp_state ) {
            local s: MCP::State;
            c$mcp_state = s;
        }

        # Create new Info record
        local info: MCP::Info;
        info$ts = network_time();
        info$uid = c$uid;
        info$id = c$id;
        info$trans_depth = ++c$mcp_state$trans_depth;
        info$msg_id = msg?$id ? msg$id : 0;
        info$method_name = msg$method;
        # ... populate request fields ...

        if ( msg?$id ) {
            # This is a REQUEST - store for later response matching
            c$mcp_state$pending[msg$id] = info;
            c$mcp = info;  # Make accessible to other events
        } else {
            # This is a NOTIFICATION - log immediately
            info$is_notification = T;
            Log::write(MCP::LOG, info);
        }
    }
    else if ( msg?$result || msg?$error ) {
        # This is a RESPONSE
        local id = msg$id;

        if ( id in c$mcp_state$pending ) {
            # Found matching request
            local req_info = c$mcp_state$pending[id];

            # Fill in response fields
            req_info$has_response = T;
            req_info$response_time = network_time() - req_info$ts;
            req_info$response_size = |data|;

            if ( msg?$result ) {
                req_info$response_status = "success";
            } else {
                req_info$response_status = "error";
                req_info$error_code = msg$error$code;
                req_info$error_message = msg$error$message;
            }

            # Log complete transaction
            Log::write(MCP::LOG, req_info);

            # Remove from pending
            delete c$mcp_state$pending[id];
        }
        # else: orphaned response (request not seen or already logged)
    }
}

# On connection close, log any orphaned requests
event connection_state_remove(c: connection)
{
    if ( ! c?$mcp_state )
        return;

    # Log all pending requests as timed out
    for ( id in c$mcp_state$pending ) {
        local info = c$mcp_state$pending[id];
        info$timed_out = T;
        Log::write(MCP::LOG, info);
    }
}
```

**SSE Streaming Responses:**

For SSE streams where multiple responses arrive for a single request (e.g., streaming completion):

```zeek
# First response completes the original transaction
# Subsequent responses create new log entries with parent_msg_id

if ( id in c$mcp_state$pending ) {
    # First response
    local req_info = c$mcp_state$pending[id];
    # ... fill fields and log ...
    delete c$mcp_state$pending[id];

    # Store msg_id for linking subsequent responses
    c$mcp_state$current_stream_id = id;
}
else if ( c$mcp_state?$current_stream_id &&
          c$mcp_state$current_stream_id == id ) {
    # Subsequent streaming response
    local stream_info: MCP::Info;
    stream_info$ts = network_time();
    stream_info$parent_msg_id = id;
    # ... populate response fields only ...
    Log::write(MCP::LOG, stream_info);
}
```

**Advantages of This Approach:**

1. **Analysis Simplicity:** Query logs with SQL/Splunk/etc. without joining
2. **Performance:** Single log write per transaction (vs. 2 for separate approach)
3. **Completeness:** Easy to identify incomplete transactions (`has_response=F`)
4. **Consistency:** Matches Zeek's HTTP, DNS, and other protocol analyzers
5. **Streaming Support:** `parent_msg_id` links multi-response scenarios

---

## HTTP to Spicy Migration Plan

### Phase 1: Spicy HTTP Grammar Development

**Objective:** Create a feature-complete HTTP/1.x grammar in Spicy

**Deliverables:**

1. **Base Grammar (`http.spicy`)**
   ```spicy
   module HTTP;

   import zeek;

   # HTTP Request Line
   public type RequestLine = unit {
       method: /[A-Z]+/;
       : /[ ]+/;
       uri: /[^ ]+/;
       : /[ ]+/;
       version: Version;
       : /\r\n/;
   };

   # HTTP Response Line
   public type ResponseLine = unit {
       version: Version;
       : /[ ]+/;
       status_code: /[0-9]{3}/;
       : /[ ]+/;
       reason: /[^\r\n]*/;
       : /\r\n/;
   };

   # HTTP Version
   type Version = unit {
       : /HTTP\//;
       major: /[0-9]/;
       : /\./;
       minor: /[0-9]/;
   };

   # HTTP Headers
   public type Headers = unit {
       headers: Header[] &until($$.is_end);
   };

   type Header = unit {
       var is_end: bool = False;

       : /\r\n/ { self.is_end = True; }
         if (self.is_end) |
       name: /[^:\r\n]+/;
       : /: */;
       value: /[^\r\n]*/;
       : /\r\n/;
   };

   # Chunked Body
   public type ChunkedBody = unit {
       chunks: Chunk[] &until($$.is_last);
       trailers: Headers;
   };

   type Chunk = unit {
       var is_last: bool = False;

       size_hex: /[0-9a-fA-F]+/;
       : /[^\r\n]*\r\n/;  # Extensions ignored
       data: bytes &size=self.chunk_size;
       : /\r\n/;

       var chunk_size: uint64 = self.size_hex.to_uint(16);

       on %done {
           self.is_last = (self.chunk_size == 0);
       }
   };

   # Full HTTP Request
   public type Request = unit {
       request_line: RequestLine;
       headers: Headers;

       # Body parsing based on headers
       switch {
           self.has_chunked_encoding -> chunked_body: ChunkedBody;
           self.has_content_length -> fixed_body: bytes &size=self.content_length;
       };

       # Helper to detect Transfer-Encoding: chunked
       var has_chunked_encoding: bool;
       var has_content_length: bool;
       var content_length: uint64;
   };

   # Full HTTP Response
   public type Response = unit {
       response_line: ResponseLine;
       headers: Headers;

       switch {
           self.has_chunked_encoding -> chunked_body: ChunkedBody;
           self.has_content_length -> fixed_body: bytes &size=self.content_length;
       };

       var has_chunked_encoding: bool;
       var has_content_length: bool;
       var content_length: uint64;
   };
   ```

2. **Event Mapping (`http.evt`)**
   ```
   protocol analyzer spicy::HTTP over TCP:
       parse originator with HTTP::Request,
       parse responder with HTTP::Response,
       port 80/tcp,
       replaces HTTP;

   on HTTP::RequestLine -> event http_request(
       $conn,
       $is_orig,
       self.method,
       self.uri,
       self.version.major + "." + self.version.minor
   );

   on HTTP::ResponseLine -> event http_reply(
       $conn,
       $is_orig,
       self.version.major + "." + self.version.minor,
       self.status_code.to_uint(),
       self.reason
   );

   on HTTP::Header -> event http_header(
       $conn,
       $is_orig,
       self.name,
       self.value
   );

   on HTTP::Request::%done -> event http_message_done(
       $conn,
       $is_orig,
       HTTP::build_message_stat(...)
   );
   ```

3. **CMake Integration**
   - Add Spicy HTTP to `src/analyzer/protocol/http/CMakeLists.txt`
   - Conditional compilation flag: `ZEEK_ENABLE_SPICY_HTTP`

**Challenges:**

1. **Header Parsing Complexity**
   - Multi-line headers (folding)
   - Case-insensitive matching
   - **Solution:** Use Spicy's `&convert` and custom parsing

2. **Chunked Encoding State**
   - Variable-length chunks
   - Trailer headers after last chunk
   - **Solution:** `&until` with dynamic termination condition

3. **Content-Length vs Chunked**
   - Mutual exclusion
   - Connection-close bodies
   - **Solution:** Conditional parsing with `switch`

4. **MIME/Multipart**
   - Nested entities
   - Boundary detection
   - **Solution:** Recursive unit definitions or separate MIME grammar

**Timeline:** 8-10 weeks

### Phase 2: Feature Parity & Testing

**Objective:** Achieve functional equivalence with C++ HTTP analyzer

**Approach:**

1. **Test-Driven Migration**
   - Run existing 45+ HTTP tests against Spicy version
   - Fix failures iteratively
   - Ensure output logs match exactly

2. **Performance Benchmarking**
   - Compare C++ vs Spicy on large traces
   - Target: <10% performance regression
   - Optimize hot paths if needed

3. **File Analysis Integration**
   - Hook Spicy events into file_mgr
   - Preserve file extraction for HTTP bodies

4. **Content Decompression**
   - Integrate gzip/deflate into Spicy parser
   - Or: Keep as post-processing step

5. **WebSocket Upgrade Handling**
   - Detect `Upgrade: websocket` header
   - Switch to WebSocket analyzer (already Spicy-based)

**Deliverables:**

- All `testing/btest/scripts/base/protocols/http/*.zeek` tests pass
- Performance report (C++ baseline vs Spicy)
- Migration guide for users

**Timeline:** 6-8 weeks

### Phase 2.5: Performance Optimization (Critical for High-Visibility Deployments)

**Context:** In deployments with TLS Inspection (TLSI) proxies or TLS termination points, Zeek visibility of HTTP traffic can increase dramatically compared to typical deployments where most HTTP is encrypted. Performance optimization is critical to handle high-volume HTTP parsing without dropping packets or impacting real-time analysis.

**Common High-Visibility Deployment Scenarios:**
- **TLSI Proxies:** Zscaler, Palo Alto, Cisco WSA decrypting enterprise traffic
- **Cloud Load Balancers:** AWS ALB, GCP Load Balancer, Azure Application Gateway with TLS termination
- **Reverse Proxies:** nginx, HAProxy, Envoy handling TLS at the edge
- **Development Environments:** Unencrypted local/staging servers

**Objective:** Minimize performance impact of HTTP/MCP parsing for high-throughput scenarios

**Key Optimization Areas:**

#### 1. Early MCP Detection and Bypass

**Problem:** Parsing all HTTP bodies as potential MCP is expensive

**Solution:** Fast-path non-MCP traffic

```zeek
# Stage 1: Header-based detection (very fast)
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( name == "CONTENT-TYPE" ) {
        if ( value == "application/json" )
            c$http$potential_mcp = T;
        else if ( value == "text/event-stream" )
            c$http$potential_sse = T;
    }
}

# Stage 2: Only inspect body if potential_mcp flag set
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    if ( ! c$http?$potential_mcp )
        return;  # Fast bypass for images, videos, etc.

    # Only regex-scan first 256 bytes for "jsonrpc"
    if ( |data| > 0 && /\"jsonrpc\":\"2\.0\"/ in data[0:min(256, |data|)] )
        c$http$is_mcp = T;
}
```

**Performance Impact:** Avoids expensive JSON parsing for 99%+ of HTTP traffic

#### 2. Content Decompression Plugin (C++ Implementation)

**Problem:** Deflate/gzip decompression in Zeek script is slow and memory-intensive

**Solution:** Native C++ plugin for decompression

**Implementation Strategy:**

```cpp
// src/analyzer/protocol/http/decompression/HTTP_Decompression.h

#pragma once

#include <zlib.h>
#include "zeek/plugin/Plugin.h"

namespace zeek::analyzer::http {

class DecompressionAnalyzer : public Analyzer {
public:
    enum Algorithm { NONE, GZIP, DEFLATE, BROTLI };

    DecompressionAnalyzer(Connection* conn, Algorithm algo);
    ~DecompressionAnalyzer() override;

    // Streaming decompression (avoids buffering entire body)
    void DeliverStream(int len, const u_char* data, bool is_orig) override;

private:
    Algorithm algorithm;
    z_stream zlib_stream;
    bool initialized;

    // Security limits
    static const size_t MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024; // 100MB
    static const double MAX_COMPRESSION_RATIO = 1000.0;
    size_t total_compressed = 0;
    size_t total_decompressed = 0;

    void CheckCompressionBomb();
};

} // namespace
```

**Security Hardening:**

1. **Compression Bomb Protection:**
   - Track compression ratio in real-time
   - Abort if ratio > 1000:1 (configurable)
   - Limit total decompressed size per connection

2. **Resource Limits:**
   - Maximum decompressed buffer size
   - Memory pool with bounds checking
   - Timeout for decompression operations

3. **Fuzzing and Testing:**
   - AFL/libFuzzer integration for zlib wrapper
   - Known-bad inputs from security advisories
   - Malformed compressed data handling

**Performance Characteristics:**
- **Streaming:** Decompresses chunks as they arrive (no full buffering)
- **Zero-copy:** Where possible, decompress directly into Zeek buffers
- **Early abort:** Stop on compression bomb detection

#### 3. Selective JSON Parsing

**Problem:** Full JSON parsing is expensive; MCP detection only needs partial parse

**Two-Stage Approach:**

**Stage 1: Fast Path (Regex-based)**
```zeek
# Quick check: Is this JSON-RPC?
if ( /\"jsonrpc\":\"2\.0\"/ !in data )
    return;  # Not JSON-RPC, skip

# Extract method (lightweight)
local method_match = find_last(data, /\"method\":\"([^\"]+)\"/);
if ( method_match == "" )
    return;  # Response or malformed

# Check if it's an MCP method we care about
if ( /^(tools|resources|prompts|sampling)\// !in method_match )
    return;  # Not MCP, skip expensive parsing
```

**Stage 2: Full Parse (Only for confirmed MCP)**
```zeek
# Now worth the cost of full JSON parsing
local msg = parse_json(data);
# ... full MCP analysis
```

**Performance Impact:** Avoids JSON parsing for non-MCP JSON-RPC traffic (e.g., other protocols)

#### 4. Configurable Content Capture Depth

**Problem:** Capturing full prompt/resource content can be memory-intensive

**Solution:** Tunable limits with smart defaults

```zeek
module MCP;

## Performance tuning options

# Maximum content to capture (0 = unlimited, risky)
option max_content_capture_size = 1024 &redef;

# Skip content capture for large responses
option skip_capture_threshold = 100000;  # 100KB

# Sampling: Only capture content for 1 in N requests
option content_capture_sample_rate = 1;  # 1 = all, 10 = 10%, etc.

# Fast-path: Skip MCP detection for small requests
option min_mcp_body_size = 50;  # Bytes
```

**Adaptive Behavior:**
```zeek
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    # Skip tiny bodies (can't be valid MCP)
    if ( length < MCP::min_mcp_body_size )
        return;

    # Skip huge bodies (likely file transfer, not MCP)
    if ( length > MCP::skip_capture_threshold ) {
        # Still log metadata, just no content
        # ...
        return;
    }

    # Sampling for reduced load
    if ( MCP::content_capture_sample_rate > 1 &&
         c$uid_hash % MCP::content_capture_sample_rate != 0 )
        return;

    # Proceed with full analysis
}
```

#### 5. Connection State Management

**Problem:** State tables can grow unbounded in long-lived connections

**Solution:** Aggressive cleanup with tunables

```zeek
# Limit pending requests per connection
option max_pending_requests = 100 &redef;

# Timeout for orphaned requests
option request_timeout = 5min &redef;

# Periodic cleanup
global pending_request_cleanup: event();

event pending_request_cleanup()
{
    local now = network_time();

    for ( cid in active_mcp_connections ) {
        local c = lookup_connection(cid);
        if ( ! c?$mcp_state )
            next;

        # Clean up old pending requests
        for ( id in c$mcp_state$pending ) {
            local req = c$mcp_state$pending[id];
            if ( now - req$ts > request_timeout ) {
                req$timed_out = T;
                Log::write(MCP::LOG, req);
                delete c$mcp_state$pending[id];
            }
        }
    }

    schedule 1min { pending_request_cleanup() };
}
```

#### 6. SSE Stream Optimization

**Problem:** Long-lived SSE connections can accumulate state

**Solution:** Windowed event tracking

```zeek
# Don't keep full history of SSE events
option max_sse_events_tracked = 1000 &redef;

# Use circular buffer for event IDs
type SSEState: record {
    event_ids: vector of string;  # Circular buffer
    event_count: count;
    write_index: count;
};

function track_sse_event(state: SSEState, event_id: string)
{
    if ( |state$event_ids| < max_sse_events_tracked ) {
        state$event_ids += event_id;
    } else {
        # Overwrite oldest
        state$event_ids[state$write_index] = event_id;
        state$write_index = (state$write_index + 1) % max_sse_events_tracked;
    }
    ++state$event_count;
}
```

**Timeline:** 3-4 weeks (parallel with Phase 2)

### Phase 3: Production Rollout

**Objective:** Replace C++ HTTP analyzer with Spicy version

**Strategy:**

1. **Gradual Rollout**
   - Week 1-2: Zeek development branch
   - Week 3-4: Beta testing with volunteers
   - Week 5-6: Bug fixes based on feedback
   - Week 7+: Mainline merge

2. **Backward Compatibility**
   - Maintain C++ version as fallback
   - Build-time option: `--with-legacy-http`
   - Default: Spicy HTTP (if Spicy available)

3. **Documentation Updates**
   - Update Zeek docs: HTTP analyzer now Spicy
   - Migration notes for plugin developers
   - Known issues and limitations

4. **Deprecation Plan**
   - Zeek 7.1: Spicy HTTP becomes default
   - Zeek 7.2: C++ HTTP marked deprecated
   - Zeek 8.0: C++ HTTP removed

**Timeline:** 4-6 weeks

---

## MCP Protocol Implementation Plan

### Phase 1: SSE Parser in Spicy

**Objective:** Add Server-Sent Events parsing capability

**SSE Format (RFC 8895):**
```
event: message
id: evt-12345
data: {"jsonrpc":"2.0","method":"tools/call",...}
data: ...continued on next line...

event: ping
```

**Spicy Grammar (`sse.spicy`):**

```spicy
module SSE;

import zeek;

# SSE Event Stream
public type EventStream = unit {
    events: Event[];
};

# Individual SSE Event
public type Event = unit {
    fields: EventField[] &until($$.is_end);
    : /\n/;  # Empty line marks end of event

    var event_type: string = "message";  # Default
    var event_id: optional<string>;
    var data: vector<string>;
    var retry: optional<uint64>;

    var is_end: bool = False;

    on %done {
        # Concatenate multi-line data fields
        self.full_data = "|".join(self.data);
    }

    var full_data: string;
};

type EventField = unit {
    var is_end: bool = False;

    : /\n/ { self.is_end = True; }
      if (self.is_end) |
    field_name: /[^:\n]+/;
    : /: ?/;
    field_value: /[^\n]*/;
    : /\n/;

    on %done {
        switch (self.field_name) {
            case "event":  parent.event_type = self.field_value;
            case "id":     parent.event_id = self.field_value;
            case "data":   parent.data.push_back(self.field_value);
            case "retry":  parent.retry = self.field_value.to_uint();
        };
    }
};
```

**Event Mapping (`sse.evt`):**

```
on SSE::Event::%done -> event sse_event(
    $conn,
    $is_orig,
    self.event_type,
    self.event_id,
    self.full_data,
    self.retry
);
```

**Integration:**
- Trigger when HTTP `Content-Type: text/event-stream`
- Switch HTTP analyzer to SSE sub-parser
- Continue parsing until connection close

**Timeline:** 3-4 weeks

### Phase 2: MCP Protocol Analyzer

**Objective:** Parse JSON-RPC messages in MCP context

**Design Decision:**

Option A: **Pure Spicy with JSON parsing**
- Use Spicy's JSON library (if available)
- Full grammar-based parsing
- **Pros:** Consistent with Spicy approach
- **Cons:** JSON in Spicy is complex

Option B: **Hybrid Spicy + Zeek Script**
- Spicy extracts JSON strings
- Zeek script parses JSON
- **Pros:** Leverage Zeek's existing JSON support
- **Cons:** Less efficient

**Recommended: Option B (Hybrid)**

**Spicy Grammar (`mcp.spicy`):**

```spicy
module MCP;

import zeek;
import HTTP;
import SSE;

# MCP over HTTP
public type MCPSession = unit {
    # Detect MCP by looking for JSON-RPC in POST body
    # or SSE events containing JSON-RPC

    switch (self.content_type) {
        case "application/json":      json_message: JSONMessage;
        case "text/event-stream":     sse_stream: SSE::EventStream;
    };

    var content_type: string;
};

type JSONMessage = unit {
    json_data: bytes &eod;

    on %done {
        # Pass to Zeek for JSON parsing
        zeek::raise_event(mcp_json_rpc_message,
                          $conn,
                          $is_orig,
                          self.json_data);
    }
};
```

**Zeek Script (`main.zeek`):**

```zeek
module MCP;

event mcp_json_rpc_message(c: connection, is_orig: bool, data: string)
{
    # Parse JSON
    local msg = parse_json(data);
    if ( ! msg )
        return;

    # Extract JSON-RPC fields
    local jsonrpc_ver = msg?$jsonrpc ? msg$jsonrpc : "";
    local method = msg?$method ? msg$method : "";
    local id = msg?$id ? msg$id : 0;

    # Classify method
    local method_type = classify_mcp_method(method);

    # Extract method-specific params
    local tool_name = "";
    local resource_uri = "";
    if ( method == "tools/call" && msg?$params )
    {
        local params = msg$params;
        tool_name = params?$name ? params$name : "";
    }

    # Build log record
    local info: Info;
    info$ts = network_time();
    info$uid = c$uid;
    info$id = c$id;
    info$is_orig = is_orig;
    info$jsonrpc_version = jsonrpc_ver;
    info$msg_type = id > 0 ? REQUEST : NOTIFICATION;
    info$method = method_type;
    info$method_name = method;
    info$msg_id = id;
    info$tool_name = tool_name;
    info$msg_size = |data|;

    Log::write(MCP::LOG, info);
}

function classify_mcp_method(method: string): MethodType
{
    if ( method == "initialize" ) return INITIALIZE;
    if ( /^tools\// in method ) {
        if ( method == "tools/call" ) return TOOLS_CALL;
        if ( method == "tools/list" ) return TOOLS_LIST;
    }
    if ( /^resources\// in method ) {
        if ( method == "resources/read" ) return RESOURCES_READ;
        if ( method == "resources/list" ) return RESOURCES_LIST;
    }
    if ( /^prompts\// in method ) {
        if ( method == "prompts/get" ) return PROMPTS_GET;
        if ( method == "prompts/list" ) return PROMPTS_LIST;
    }
    if ( /^sampling\// in method ) return SAMPLING_CREATE_MESSAGE;

    return OTHER;
}
```

**Timeline:** 5-6 weeks

### Phase 3: MCP Detection & Correlation

**Objective:** Automatically detect MCP traffic and correlate with HTTP

**Detection Heuristics:**

1. **HTTP POST to known MCP paths:**
   - `/mcp`
   - `/v1/mcp`
   - User-configurable patterns

2. **Content-Type indicators:**
   - `application/json` with JSON-RPC structure
   - POST body contains `"jsonrpc":"2.0"`

3. **SSE with MCP endpoints:**
   - GET request to MCP path
   - Response: `Content-Type: text/event-stream`

4. **Header signatures:**
   - `X-MCP-Version: 1.0`
   - Custom headers (if standardized)

**Correlation Strategy:**

```zeek
# Enhance HTTP analyzer to flag MCP
event http_request(c: connection, method: string, uri: string, ...)
{
    if ( method == "POST" && is_mcp_endpoint(uri) )
        c$http$is_mcp = T;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( name == "CONTENT-TYPE" && value == "application/json" )
        # Potential MCP - await body
        mark_for_json_inspection(c);
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    if ( should_inspect_json(c) )
    {
        if ( /\"jsonrpc\":\"2\.0\"/ in data )
            c$http$is_mcp = T;
    }
}
```

**Timeline:** 3-4 weeks

### Phase 4: Advanced Features

**Objective:** Enhance MCP analysis with security-focused features

**Features:**

1. **Tool Invocation Tracking**
   - Track which tools are called
   - Flag high-risk tools (file access, code execution)
   - Alert on unusual tool patterns

2. **Resource Access Logging**
   - Track resource URIs accessed
   - Build access graph per connection
   - Detect sensitive resource exposure

3. **Sampling Request Analysis**
   - Log when AI requests completions
   - Track model names and parameters
   - Privacy: Avoid logging prompt content

4. **Error Analysis**
   - Track JSON-RPC errors
   - Flag authentication failures
   - Detect protocol violations

5. **Performance Metrics**
   - Request/response latency
   - SSE reconnection frequency
   - Tool execution time

**Timeline:** 4-6 weeks

---

## Testing Strategy

### Unit Tests

**Spicy Grammar Tests:**

```
testing/btest/spicy/http/
├── chunk-basic.test          # Simple chunked encoding
├── chunk-trailer.test        # Trailing headers
├── chunk-extensions.test     # Chunk extensions
├── sse-basic.test            # SSE event parsing
├── sse-multiline.test        # Multi-line data fields
└── sse-resume.test           # Event ID tracking

testing/btest/spicy/mcp/
├── jsonrpc-request.test      # Basic JSON-RPC request
├── jsonrpc-response.test     # JSON-RPC response
├── jsonrpc-error.test        # Error handling
├── tools-call.test           # Tool invocation
├── resources-read.test       # Resource access
└── sse-mcp.test              # MCP over SSE
```

### Integration Tests

**HTTP Backward Compatibility:**

```bash
# Run all existing HTTP tests with Spicy version
cd testing/btest
btest -j 8 scripts/base/protocols/http/

# Expected: All tests pass with identical output
```

**MCP End-to-End:**

```
testing/btest/scripts/protocols/mcp/
├── basic-handshake.test      # MCP initialize
├── tool-invocation.test      # tools/call flow
├── sse-streaming.test        # Multiple responses
├── error-handling.test       # Error responses
└── mixed-http-mcp.test       # Regular HTTP + MCP
```

### Trace-Based Tests

**Capture Real MCP Traffic:**

1. Set up MCP server (e.g., using Anthropic SDK)
2. Capture traffic: `tcpdump -i lo -w mcp-sample.pcap port 8080`
3. Run Zeek: `zeek -r mcp-sample.pcap scripts/base/protocols/mcp`
4. Verify logs: `mcp.log`, `http.log`, `conn.log`

**Test Scenarios:**

- Claude Desktop → MCP server
- Custom MCP client → GitHub MCP server
- Streamable HTTP transport
- Legacy HTTP+SSE transport

### Performance Tests

**Critical for High-Visibility Deployments:** Performance testing must include high-volume HTTP scenarios typical of TLS inspection proxies, TLS termination points, and development environments where Zeek has full visibility into HTTP traffic.

**Test Scenarios:**

#### 1. Baseline Comparison

```bash
# Baseline: Current C++ HTTP
zeek -r large-http-trace.pcap -b base/protocols/http

# New: Spicy HTTP (no MCP)
zeek -r large-http-trace.pcap -b spicy/protocols/http

# With MCP analyzer enabled
zeek -r large-http-trace.pcap -b spicy/protocols/http base/protocols/mcp

# Compare: Memory, CPU, throughput, packet drops
```

#### 2. High-Visibility Deployment Simulation

**High-Volume HTTP Test:**
- **Trace:** 10GB+ PCAP with mixed HTTP traffic (80% non-MCP, 20% MCP)
- **Compression:** 50% of bodies gzip-encoded (realistic TLSI/LB scenario)
- **Connections:** 10,000+ concurrent connections
- **Duration:** 1 hour of traffic
- **Scenarios:** TLSI proxy traffic, load balancer backend traffic, dev environment

**Metrics to Track:**
```bash
# CPU utilization
perf stat -e cycles,instructions,cache-misses zeek -r high-visibility.pcap

# Memory profiling
valgrind --tool=massif zeek -r high-visibility.pcap
ms_print massif.out.* | less

# Packet capture stats
zeek -r high-visibility.pcap 2>&1 | grep "packets received\|packets dropped"

# Event processing lag
zeek -r high-visibility.pcap --pseudo-realtime=1.0  # Real-time simulation
```

#### 3. MCP-Specific Load Testing

**Pure MCP Traffic:**
- **Test:** 100% MCP traffic with various operations
- **Tools:** 40% of requests
- **Resources:** 30% of requests
- **Prompts:** 20% of requests
- **Sampling:** 10% of requests

**Measure:**
- JSON parsing overhead
- State table growth
- Log write performance

```bash
# Generate synthetic MCP traffic
python generate_mcp_pcap.py \
    --tools 40 --resources 30 --prompts 20 --sampling 10 \
    --duration 3600 --rate 1000  # 1000 req/sec for 1 hour

zeek -r synthetic-mcp.pcap base/protocols/mcp
```

#### 4. Decompression Performance

**Compression Bomb Resilience:**
```bash
# Test 1: Normal compressed data
zeek -r gzip-normal.pcap

# Test 2: High compression ratio (100:1)
zeek -r gzip-high-ratio.pcap

# Test 3: Compression bomb attempt (10000:1)
zeek -r gzip-bomb.pcap  # Should abort gracefully

# Measure:
# - Decompression time per MB
# - Memory usage during decompression
# - Detection of compression bombs
```

**Streaming vs. Buffered:**
```bash
# Compare streaming (optimized) vs. full buffering
zeek -r chunked-transfer.pcap  # Should use streaming

# Measure peak memory:
/usr/bin/time -v zeek -r chunked-transfer.pcap 2>&1 | grep "Maximum resident"
```

#### 5. Scalability Testing

**Horizontal Scaling:**
```bash
# Single worker
zeek -r bi-proxy.pcap

# Cluster mode (4 workers)
zeek -r bi-proxy.pcap --cluster=4

# Measure scaling efficiency
# Expected: 3.5x throughput with 4 workers (87.5% efficiency)
```

**Connection State Stress:**
```bash
# Many concurrent connections with MCP
zeek -r 10k-concurrent-mcp.pcap

# Monitor:
# - State table size over time
# - Memory growth rate
# - Cleanup effectiveness
```

#### 6. Comparative Benchmarks

**Against Other Tools:**
```bash
# Zeek (baseline)
time zeek -r http-traffic.pcap base/protocols/http

# Zeek + MCP
time zeek -r http-traffic.pcap base/protocols/http base/protocols/mcp

# Suricata (for reference)
time suricata -r http-traffic.pcap -c suricata.yaml

# Compare: Processing speed (packets/sec)
```

**Acceptance Criteria (Updated for High-Visibility Deployments):**

| Metric | Target | Rationale |
|--------|--------|-----------|
| **Throughput (HTTP-only)** | >= 95% of C++ | Minor regression acceptable |
| **Throughput (HTTP+MCP)** | >= 85% of C++ HTTP | MCP overhead is additional feature |
| **Memory (no MCP)** | <= 110% of C++ | Spicy may use more memory |
| **Memory (with MCP)** | <= 150% of C++ HTTP | State tracking overhead |
| **Packet drops (1Gbps)** | 0% | Must handle line rate (TLSI/LB) |
| **Packet drops (10Gbps)** | < 1% | With clustering |
| **Latency (event processing)** | < 10% increase | Real-time constraint |
| **JSON parse time** | < 1ms per message | For responsiveness |
| **Decompression (gzip)** | > 500 MB/s | zlib performance |
| **Compression bomb detection** | < 100ms | Fast abort |

**Red Flags (Performance Failures):**

- Packet drops on typical TLSI/TLS termination traffic (< 1Gbps sustained)
- Memory growth over time (leak)
- CPU usage > 80% on single core (should parallelize)
- Decompression slower than 100 MB/s
- Failure to detect compression bombs
- Event processing lag > 5 seconds

**Performance Regression Testing:**

```bash
# Automated performance CI
.github/workflows/performance-test.yml

# Run on every PR affecting HTTP/MCP
steps:
  - name: Performance Benchmark
    run: |
      # Baseline
      zeek -r perf-test.pcap > /dev/null

      # Capture metrics
      /usr/bin/time -v zeek -r perf-test.pcap 2> metrics.txt

      # Compare to baseline (fail if > 10% regression)
      python compare_performance.py metrics.txt baseline.txt
```

**Load Testing in Production-Like Environment:**

Before production deployment:
1. **Shadow mode:** Run new analyzer alongside C++ version, compare outputs
2. **Canary deployment:** Enable on 10% of sensors, monitor for 1 week
3. **Gradual rollout:** 25% → 50% → 100% over 1 month
4. **Rollback plan:** Keep C++ version for quick revert if issues arise

### Regression Prevention

**CI/CD Integration:**

- GitHub Actions workflow
- Run full test suite on every PR
- Block merge if tests fail
- Performance regression alerts (>10% slowdown blocks merge)
- Automated nightly performance benchmarks
- Memory leak detection with valgrind

---

## Additional Performance Risks and Mitigations

### Risk 1: JSON Parsing Becoming a Bottleneck

**Scenario:** In heavy MCP traffic, parsing JSON for every request/response could saturate CPU

**Indicators:**
- `parse_json()` showing up in profiling as hot path
- CPU utilization spikes during MCP-heavy periods
- Event queue backlog growing

**Mitigations:**

1. **Fast-Path Filtering (already planned):**
   - Only parse JSON if body contains `"jsonrpc"`
   - Skip JSON parsing for non-MCP methods

2. **Consider Native JSON Parser:**
   - Option: C++ JSON parser plugin (rapidjson, simdjson)
   - Benefit: 5-10x faster than Zeek script parsing
   - Trade-off: More complex, needs security hardening

3. **Lazy Parsing:**
   - Extract only needed fields (method, id) initially
   - Full parse only if detailed logging enabled
   - Example: Use regex to extract `method` without full JSON parse

4. **Parser Pool:**
   - Pre-allocate JSON parser objects
   - Reuse across connections
   - Avoid allocation overhead

**Benchmark Target:**
- JSON parsing should not exceed 20% of total CPU time
- If exceeded, consider native parser plugin

### Risk 2: State Table Growth in Long-Lived Connections

**Scenario:** TLSI proxies and load balancers often have very long-lived connections (hours/days) with MCP

**Indicators:**
- Memory usage grows linearly with uptime
- `|pending| table size` warnings
- Out-of-memory crashes on long-running sensors

**Mitigations:**

1. **Aggressive Timeouts (already planned):**
   - 5-minute timeout for orphaned requests (configurable)
   - Periodic cleanup every 1 minute

2. **Connection-Level Limits:**
   ```zeek
   option max_mcp_requests_per_connection = 10000 &redef;

   if ( c$mcp_state$trans_depth > max_mcp_requests_per_connection ) {
       # Log warning
       Reporter::conn_weird("MCP_excessive_requests", c);
       # Reset state to prevent unbounded growth
       delete c$mcp_state;
   }
   ```

3. **LRU Eviction:**
   - If pending table grows too large, evict oldest entries
   - Log evicted requests as timed out

4. **Monitoring:**
   - Export metrics: `max_pending_size`, `avg_pending_size`
   - Alert if sustained growth detected

**Benchmark Target:**
- Memory per connection should plateau after ~100 requests
- No more than 100MB memory growth per 10,000 connections

### Risk 3: Log Write Performance

**Scenario:** High-volume MCP traffic generates massive log writes

**Indicators:**
- Log writing saturates disk I/O
- Event processing lags behind packet capture
- `Log::write()` shows in profiling

**Mitigations:**

1. **Buffered Logging:**
   - Batch log writes (already Zeek default)
   - Tune buffer size: `Log::default_rotation_interval`

2. **Async Logging:**
   - Use separate thread for log writing
   - Zeek's logger framework already does this

3. **Log Sampling (for extreme volume):**
   ```zeek
   option mcp_log_sample_rate = 1 &redef;  # 1 = all, 10 = 10%

   # In log_write logic:
   if ( mcp_log_sample_rate > 1 &&
        request_counter % mcp_log_sample_rate != 0 )
       return;  # Skip this log entry

   Log::write(MCP::LOG, info);
   ```

4. **Remote Logging:**
   - Stream logs to remote collector (Kafka, syslog)
   - Offload I/O from sensor

**Benchmark Target:**
- Log writes should not cause >5% CPU usage
- No event processing lag due to logging

### Risk 4: Decompression Attack Surface

**Scenario:** Malicious compressed data attempts to crash or DoS Zeek

**Attack Vectors:**
1. **Compression bombs:** 1KB → 10GB decompressed
2. **Malformed zlib streams:** Trigger buffer overflows
3. **Infinite decompression:** Never-ending compressed stream
4. **Memory exhaustion:** Massive decompressed data

**Mitigations (already planned, but emphasize):**

1. **Compression Ratio Monitoring:**
   ```cpp
   void DecompressionAnalyzer::CheckCompressionBomb() {
       double ratio = (double)total_decompressed / total_compressed;
       if (ratio > MAX_COMPRESSION_RATIO) {
           // Log weird, abort decompression
           EmitWeird("HTTP_compression_bomb");
           initialized = false;
       }
   }
   ```

2. **Size Limits:**
   - Absolute max decompressed size: 100MB (configurable)
   - Per-chunk limit: 10MB
   - Timeout: Abort if decompression takes >5 seconds

3. **Safe zlib Usage:**
   - Use `inflateInit2()` with bounds
   - Set `avail_out` to limited buffer
   - Check return codes strictly

4. **Fuzzing:**
   - AFL fuzzing of decompression code
   - Include zlib CVE test cases
   - Continuous fuzzing in CI

**Benchmark Target:**
- Compression bomb detected within 100ms
- No crashes on malformed data
- Graceful degradation (skip decompression, log warning)

### Risk 5: Spicy Grammar Performance

**Scenario:** Spicy-generated code slower than hand-optimized C++

**Indicators:**
- Spicy HTTP >10% slower than C++ HTTP
- Packet drops in high-load testing
- Hot paths in generated Spicy code

**Mitigations:**

1. **Profile Spicy Code:**
   ```bash
   perf record zeek -r test.pcap base/protocols/http
   perf report
   # Identify hot spots in generated code
   ```

2. **Spicy Optimization Flags:**
   - Use `--optimize` during Spicy compilation
   - Consider `--enable-lto` for link-time optimization

3. **Selective C++ Fallback:**
   - If specific grammar rules are slow, replace with C++ helper
   - Example: Complex header parsing → C++ function

4. **Collaborate with Spicy Team:**
   - Report performance issues
   - Work on Spicy compiler optimizations

5. **Conditional Features:**
   - Disable expensive features in production
   - Example: MIME parsing only if needed

**Benchmark Target:**
- Spicy HTTP within 5% of C++ HTTP performance
- If not achievable, maintain C++ option

### Risk 6: Memory Fragmentation

**Scenario:** Long-running Zeek with MCP causes memory fragmentation

**Indicators:**
- Memory usage grows but `top` shows no leaks
- Performance degrades over time
- Heap fragmentation visible in valgrind

**Mitigations:**

1. **Memory Pools:**
   - Use Zeek's object pools for frequently allocated structs
   - Pre-allocate MCP::Info objects

2. **Periodic Restarts:**
   - Recommend sensor restarts every 7 days
   - Document in deployment guide

3. **Memory Allocator:**
   - Consider jemalloc or tcmalloc
   - Better fragmentation resistance

**Benchmark Target:**
- Memory should stabilize after 24 hours of runtime
- <10% memory growth over 7 days

---

## Timeline and Milestones

### Overall Project Timeline: 30-36 weeks (~7-9 months)

```
Month 1-2: HTTP to Spicy Grammar (Phase 1)
   Week 1-4:   Spicy HTTP grammar development
   Week 5-8:   Chunked encoding & headers
   Week 9-10:  Initial testing

Month 3-4: HTTP Feature Parity (Phase 2)
   Week 11-14: Test-driven feature completion
   Week 15-16: Performance optimization
   Week 17-18: File analysis integration

Month 5: HTTP Production (Phase 3)
   Week 19-20: Beta testing
   Week 21-22: Bug fixes & rollout

Month 6: SSE & MCP Foundation
   Week 23-26: SSE parser in Spicy (MCP Phase 1)

Month 7-8: MCP Protocol Analyzer
   Week 27-31: MCP JSON-RPC parsing (MCP Phase 2)
   Week 32-35: MCP detection & correlation (MCP Phase 3)

Month 9: MCP Advanced & Testing
   Week 36-38: Advanced MCP features (MCP Phase 4)
   Week 39-40: Final testing & documentation
```

### Key Milestones

**M1: Spicy HTTP Grammar Complete** (Week 10)
- All grammar elements defined
- Basic request/response parsing works
- Chunked encoding functional

**M2: HTTP Feature Parity Achieved** (Week 18)
- All 45+ tests pass
- Performance within 10% of C++
- File extraction works

**M3: HTTP Spicy in Production** (Week 22)
- Merged to master
- Documentation updated
- C++ version deprecated

**M4: SSE Parser Ready** (Week 26)
- SSE events parsed correctly
- Event ID tracking works
- Integration with HTTP complete

**M5: MCP Logs Generated** (Week 31)
- `mcp.log` populated correctly
- JSON-RPC messages classified
- Tool/resource tracking works

**M6: MCP Detection Automated** (Week 35)
- MCP traffic auto-detected
- Correlation with HTTP solid
- No manual configuration needed

**M7: MCP Production Ready** (Week 40)
- Full test suite passes
- Documentation complete
- Community feedback incorporated

### Dependencies

**Critical Path:**

```
HTTP Spicy Grammar → HTTP Testing → HTTP Production
                                         ↓
                                    SSE Parser
                                         ↓
                                   MCP Analyzer
                                         ↓
                                  MCP Detection
                                         ↓
                                MCP Advanced Features
```

**External Dependencies:**

- Spicy framework updates (if needed for JSON)
- Community testing and feedback
- Zeek core team code review

### Risk Mitigation

**Risk 1: Spicy HTTP performance insufficient**
- **Mitigation:** Benchmark early (Week 8)
- **Fallback:** Keep C++ version, defer migration

**Risk 2: JSON parsing too complex in Spicy**
- **Mitigation:** Use hybrid Spicy+Zeek approach
- **Fallback:** Full Zeek-script JSON parsing

**Risk 3: MCP spec changes during development**
- **Mitigation:** Track MCP spec via GitHub
- **Contingency:** Plan for spec version handling

**Risk 4: Community resistance to HTTP migration**
- **Mitigation:** Long deprecation period
- **Option:** Maintain both analyzers long-term

---

## AI-Assisted Development Estimates

This section provides estimates for development with AI assistance (Claude Code or similar). These complement the human-only estimates in the Timeline section above.

### Methodology

AI-assisted development estimates consider:
- **Token consumption** for context and generation
- **Human time** for review, testing, and iteration
- **Wall clock time** including AI generation, human feedback cycles, and testing
- **Iteration cycles** typical for AI-generated code quality

**Assumptions:**
- Developer experienced with Zeek and Spicy
- Claude Code (Sonnet 4.5 or similar) as AI assistant
- ~200K token budget per session
- Human reviews all AI-generated code
- Testing infrastructure already in place

### Phase-by-Phase Estimates

#### HTTP to Spicy Migration

| Phase | Human-Only | AI-Assisted (Tokens) | AI-Assisted (Human Time) | AI-Assisted (Wall Clock) | Notes |
|-------|------------|---------------------|--------------------------|-------------------------|--------|
| **Phase 1: Spicy Grammar** | 8-10 weeks | 2-3M tokens | 3-4 weeks | 4-5 weeks | AI can generate grammar quickly, but iterations needed for edge cases |
| **Phase 2: Feature Parity** | 6-8 weeks | 3-4M tokens | 3-4 weeks | 4-6 weeks | AI helps with test failures, but debugging is human-intensive |
| **Phase 2.5: Performance** | 3-4 weeks | 1-2M tokens | 2-3 weeks | 3-4 weeks | Profiling and optimization requires human expertise |
| **Phase 3: Production** | 4-6 weeks | 500K-1M tokens | 3-4 weeks | 4-6 weeks | Rollout, beta testing mostly human-driven |
| **HTTP Total** | **21-28 weeks** | **7-10M tokens** | **11-15 weeks** | **15-21 weeks** | **~40-50% time reduction** |

#### MCP Implementation

| Phase | Human-Only | AI-Assisted (Tokens) | AI-Assisted (Human Time) | AI-Assisted (Wall Clock) | Notes |
|-------|------------|---------------------|--------------------------|-------------------------|--------|
| **MCP Phase 1: SSE** | 3-4 weeks | 800K-1.2M tokens | 1.5-2 weeks | 2-3 weeks | Well-defined protocol, AI can generate parser efficiently |
| **MCP Phase 2: JSON-RPC** | 5-6 weeks | 1.5-2M tokens | 2-3 weeks | 3-4 weeks | AI handles JSON parsing logic well |
| **MCP Phase 3: Detection** | 3-4 weeks | 1-1.5M tokens | 1.5-2 weeks | 2-3 weeks | Heuristics benefit from AI pattern generation |
| **MCP Phase 4: Advanced** | 4-6 weeks | 1.5-2M tokens | 2-3 weeks | 3-4 weeks | Security features need careful human review |
| **MCP Total** | **15-20 weeks** | **4.8-6.7M tokens** | **7.5-10 weeks** | **10-14 weeks** | **~45-50% time reduction** |

### Overall Project Estimates

| Metric | Human-Only | AI-Assisted | Reduction |
|--------|------------|-------------|-----------|
| **Total Duration** | 30-36 weeks (7-9 months) | 18-25 weeks (4-6 months) | **40-45%** |
| **Token Budget** | N/A | 12-17M tokens | - |
| **Human Time** | 30-36 weeks | 18.5-25 weeks | **35-40%** |
| **Sessions Required** | N/A | 60-85 sessions (~200K tokens each) | - |

### Detailed Token Breakdown by Activity

#### Phase 1: Spicy HTTP Grammar (2-3M tokens)

**Grammar Generation (800K-1M tokens)**
- Initial HTTP grammar structure: 50K tokens
- Request/response parsing: 100K tokens
- Header parsing with edge cases: 150K tokens
- Chunked encoding implementation: 200K tokens
- Version handling and status codes: 100K tokens
- Integration with Zeek events: 200K tokens
- Iterations and refinements (3-5 cycles): 200K tokens

**Testing & Debugging (800K-1M tokens)**
- Test case generation: 150K tokens
- Debugging parse failures: 300K tokens
- Edge case handling: 200K tokens
- Performance profiling analysis: 150K tokens
- Documentation generation: 200K tokens

**Context Management (400K-600K tokens)**
- Re-reading existing HTTP analyzer: 300K tokens
- Zeek API reference lookups: 150K tokens
- Spicy documentation consultation: 150K tokens

#### Phase 2: Feature Parity (3-4M tokens)

**Test-Driven Development (1.5-2M tokens)**
- Running and analyzing 45+ test failures: 500K tokens
- Fixing each test iteratively (~40K/test): 1.8M tokens
- Regression testing: 200K tokens

**Feature Implementation (1-1.5M tokens)**
- File analysis integration: 300K tokens
- Content decompression: 300K tokens
- WebSocket upgrade handling: 200K tokens
- Authentication parsing: 200K tokens
- Error handling improvements: 200K tokens

**Context & Documentation (500K-700K tokens)**
- Re-reading modified code: 400K tokens
- Updating documentation: 300K tokens

#### Phase 2.5: Performance Optimization (1-2M tokens)

**C++ Plugin Development (600K-800K tokens)**
- Decompression plugin design: 150K tokens
- Implementation with security checks: 300K tokens
- Zeek API integration: 150K tokens
- Testing compression bomb scenarios: 200K tokens

**Optimization Implementation (400K-600K tokens)**
- Early MCP detection logic: 150K tokens
- Selective JSON parsing: 150K tokens
- Connection state optimization: 150K tokens
- SSE stream handling: 150K tokens

**Benchmarking Analysis (200K-400K tokens)**
- Performance test analysis: 200K tokens
- Optimization recommendations: 200K tokens

#### MCP Phase 1: SSE Parser (800K-1.2M tokens)

**SSE Grammar (400K-500K tokens)**
- SSE event parsing: 150K tokens
- Multi-line data handling: 100K tokens
- Event ID tracking: 100K tokens
- Integration with HTTP: 150K tokens

**Testing (300K-500K tokens)**
- Test case creation: 150K tokens
- Edge case debugging: 200K tokens
- Documentation: 150K tokens

**Context (100K-200K tokens)**
- SSE RFC consultation: 100K tokens
- MCP transport spec review: 100K tokens

#### MCP Phase 2: JSON-RPC Parser (1.5-2M tokens)

**Zeek Script Implementation (800K-1M tokens)**
- JSON-RPC message parsing: 200K tokens
- Method classification logic: 200K tokens
- Request/response correlation: 300K tokens
- Error handling: 200K tokens

**Log Format Implementation (400K-600K tokens)**
- MCP::Info record structure: 150K tokens
- Logging event handlers: 200K tokens
- Privacy/security configurations: 200K tokens

**Testing & Iteration (300K-400K tokens)**
- Test MCP conversations: 200K tokens
- Edge case handling: 200K tokens

#### MCP Phase 3: Detection & Correlation (1-1.5M tokens)

**Heuristics Implementation (500K-700K tokens)**
- MCP endpoint detection: 150K tokens
- Content-Type analysis: 100K tokens
- SSE correlation logic: 200K tokens
- Header signature matching: 150K tokens

**Integration Testing (500K-800K tokens)**
- Full pipeline testing: 400K tokens
- False positive analysis: 200K tokens
- Documentation: 200K tokens

#### MCP Phase 4: Advanced Features (1.5-2M tokens)

**Security Features (700K-1M tokens)**
- Tool invocation tracking: 250K tokens
- Resource access logging: 250K tokens
- Error analysis: 200K tokens
- Alert generation: 300K tokens

**Testing & Documentation (800K-1M tokens)**
- Comprehensive test suite: 400K tokens
- Security review: 200K tokens
- User documentation: 400K tokens

### Key Factors Affecting AI Assistance Effectiveness

**High AI Value (50-70% time reduction):**
- Grammar generation (syntax is AI's strength)
- Boilerplate code (events, logging, records)
- Test case generation
- Documentation writing
- Pattern matching and heuristics
- Error handling code

**Medium AI Value (30-50% time reduction):**
- Debugging test failures (AI suggests, human confirms)
- Performance optimization (AI proposes, human profiles)
- Integration code (requires understanding both systems)
- Edge case handling (AI generates, human validates)

**Low AI Value (10-30% time reduction):**
- Beta testing and rollout (human-intensive)
- Community feedback integration (requires judgment)
- Performance profiling (requires real environment)
- Security hardening (requires expertise)
- Production monitoring (operational task)

### Session Planning

**Typical AI-Assisted Session:**
- **Budget:** 200K tokens
- **Duration:** 2-4 hours (wall clock)
- **Human time:** 1-2 hours (review + feedback)
- **Coverage:** 1-2 days of solo development work

**Example Session Breakdown:**
1. Context loading (30K tokens): Read relevant files, previous work
2. Task planning (10K tokens): Break down work, create todos
3. Implementation (80K tokens): Generate code, tests
4. Iteration (50K tokens): Fix issues, refine based on feedback
5. Documentation (20K tokens): Comments, commit messages
6. Buffer (10K tokens): Unexpected issues

**Recommended Workflow:**
- **Week 1-2:** Daily sessions (5 sessions/week) for rapid prototyping
- **Week 3+:** 3-4 sessions/week for refinement and testing
- **Testing phases:** 2-3 sessions/week (more human-driven)
- **Rollout phases:** 1-2 sessions/week (mostly human work)

### Cost Estimates

**Token Costs (assuming Claude API pricing):**
- Input tokens: ~$3 per million
- Output tokens: ~$15 per million
- Typical ratio: 40% input, 60% output

**Total Project Token Cost:**
- Input: ~5-7M tokens × $3/M = $15-21
- Output: ~7-10M tokens × $15/M = $105-150
- **Total: $120-170** (for AI assistance only)

**Human Cost Comparison:**
- Senior developer: ~$80-120/hour
- Human-only: 30-36 weeks × 40 hours × $100 = $120,000-144,000
- AI-assisted: 18.5-25 weeks × 40 hours × $100 + $150 = $74,000-100,000
- **Savings: $20,000-44,000 (15-30%)**

Note: Assumes developer time remains constant (senior level). In practice, AI assistance may enable less experienced developers to accomplish the same work, multiplying cost savings.

### Risks and Limitations

**AI-Generated Code Risks:**
1. **Subtle bugs in edge cases** - Requires thorough testing
2. **Performance issues** - AI may not optimize for Zeek's architecture
3. **Security vulnerabilities** - Human security review essential
4. **Maintainability concerns** - AI code may be verbose or unclear

**Mitigation Strategies:**
- **100% human review** of all generated code
- **Comprehensive testing** against existing test suite
- **Performance benchmarking** at each phase
- **Security review** by experienced Zeek developer
- **Iterative refinement** based on real-world testing

**When AI Assistance Is Less Effective:**
- Complex debugging requiring deep system knowledge
- Performance optimization needing profiling tools
- Production rollout and monitoring
- Community engagement and feedback integration
- Design decisions requiring domain expertise

---

## References

### Zeek Resources

- **Main Repository:** https://github.com/zeek/zeek
- **Documentation:** https://docs.zeek.org
- **Current HTTP Analyzer:** `src/analyzer/protocol/http/`
- **Spicy Integration:** `src/spicy/`
- **Testing Framework:** `testing/btest/`

### MCP Resources

- **MCP Specification:** https://spec.modelcontextprotocol.io/
- **MCP GitHub:** https://github.com/modelcontextprotocol
- **Anthropic MCP Docs:** https://docs.anthropic.com/en/docs/mcp
- **Streamable HTTP:** https://spec.modelcontextprotocol.io/specification/2025-06-18/basic/transports

### Spicy Resources

- **Spicy Documentation:** https://docs.zeek.org/projects/spicy
- **Spicy Analyzers (Examples):** https://github.com/zeek/spicy-analyzers
- **TFTP Tutorial:** https://docs.zeek.org/projects/spicy/en/latest/tutorial/
- **Zeek Integration Guide:** https://docs.zeek.org/en/master/devel/spicy/

### Standards

- **RFC 7230:** HTTP/1.1 Message Syntax and Routing
- **RFC 7231:** HTTP/1.1 Semantics and Content
- **RFC 8895:** Server-Sent Events (SSE)
- **JSON-RPC 2.0:** https://www.jsonrpc.org/specification

### Related Protocols

- **WebSocket:** Already in Zeek (Spicy-based)
- **HTTP/2:** Future consideration
- **HTTP/3 (QUIC):** Already in Zeek (Spicy-based)

---

## Appendices

### Appendix A: Zeek Log Format Examples

**http.log (current format):**
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#fields	ts uid id.orig_h id.orig_p id.resp_h id.resp_p trans_depth method host uri referrer version user_agent origin request_body_len response_body_len status_code status_msg info_code info_msg tags username password proxied orig_fuids orig_filenames orig_mime_types resp_fuids resp_filenames resp_mime_types
```

**conn.log (for reference):**
```
#fields	ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents
```

### Appendix B: MCP Message Examples

**Initialize Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "1.0",
        "capabilities": {
            "tools": {},
            "resources": {}
        },
        "clientInfo": {
            "name": "ExampleClient",
            "version": "1.0.0"
        }
    }
}
```

**Initialize Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "1.0",
        "capabilities": {
            "tools": {},
            "resources": {},
            "prompts": {}
        },
        "serverInfo": {
            "name": "ExampleServer",
            "version": "1.0.0"
        }
    }
}
```

**Tool Call Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
        "name": "get_user_info",
        "arguments": {
            "user_id": "12345"
        }
    }
}
```

**SSE Event Stream:**
```
event: message
id: msg-001
data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Hello"}]}}

event: message
id: msg-002
data: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"World"}]}}
```

### Appendix C: Spicy vs C++ Feature Comparison

| Feature | C++ HTTP | Spicy HTTP | Notes |
|---------|----------|------------|-------|
| HTTP/1.0 | ✅ | ✅ | Full support |
| HTTP/1.1 | ✅ | ✅ | Full support |
| Chunked TE | ✅ | ✅ | State machine |
| Keep-alive | ✅ | ✅ | Connection tracking |
| Pipelining | ✅ | ✅ | Request queuing |
| gzip/deflate | ✅ | ⚠️ | May need plugin |
| MIME parsing | ✅ | ⚠️ | Complex nesting |
| WebSocket upgrade | ✅ | ✅ | Handoff to WS analyzer |
| File extraction | ✅ | ✅ | Via file_mgr hooks |
| Performance | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 10-15% slower expected |
| Maintainability | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Grammar > C++ |

### Appendix D: Security Considerations

**Deployment Context:**

Zeek will only see unencrypted MCP traffic in specific deployment scenarios:
- **TLS Inspection (TLSI) proxies:** Enterprise security proxies that decrypt/inspect/re-encrypt traffic (Zscaler, Palo Alto, etc.)
- **TLS termination points:** Load balancers or reverse proxies handling TLS, with Zeek monitoring backend traffic
- **Development/testing environments:** Unencrypted servers during development
- **Internal service mesh:** Microservices communicating over unencrypted HTTP within trusted networks

In these contexts, Zeek already has access to the full HTTP content, so the primary concerns are:
1. **What to log** for security/analysis purposes
2. **How to handle sensitive data** (PII, credentials, PCI data, etc.)
3. **Configurability** to balance visibility with privacy

---

**Understanding MCP Primitives (for Privacy Analysis):**

**1. Resources (`resources/read`):**
- **What they are:** Read-only data fetched over MCP (not via direct file:// or http:// access)
- **URI examples:** `file:///etc/config.yaml`, `database://prod/schema`, `git://repo/history`
- **Content transfer:** The MCP server fetches the resource and returns full content in JSON-RPC response
- **Privacy risk:** HIGH - Content can be large, proprietary, or contain sensitive data
- **Logging strategy:**
  - Always log: Resource URI (identifier)
  - Optional: Content preview (truncated, controlled by `capture_resource_preview`)
  - Always log: Content size for forensics

**2. Prompts (`prompts/get`):**
- **What they are:** User-selected, server-defined reusable templates with arguments
- **Examples:** `git-commit`, `explain-code`, `debug-error`
- **Content:** Templates return structured messages/instructions for the LLM
- **Privacy risk:** MEDIUM - Prompt arguments may contain business logic or queries
- **Logging strategy:**
  - Always log: Prompt name (e.g., `git-commit`)
  - Optional: Prompt description (if server provides)
  - Optional: Full prompt content (controlled by `capture_prompt_content`)
  - Always log: Arguments (truncated, may need redaction)

**3. Tools (`tools/call`):**
- **What they are:** Executable functions the LLM can invoke
- **Examples:** `execute_query`, `read_file`, `make_api_call`, `run_code`
- **Arguments:** Can contain queries, code, API parameters, file paths
- **Privacy risk:** VERY HIGH - Arguments often contain sensitive operations/data
- **Logging strategy:**
  - Always log: Tool name
  - Always log: Arguments (truncated, with redaction)
  - Consider: Pattern-based redaction for known sensitive patterns

**4. Sampling (`sampling/createMessage`):**
- **What it is:** Client requesting LLM to generate completions
- **Content:** The full prompt context sent to the LLM (user input + context)
- **Privacy risk:** EXTREME - Can contain anything the user typed
- **Logging strategy:**
  - Always log: Model name, metadata
  - Optional: Prompt content (controlled by `capture_sampling_prompts`)
  - Default: Do NOT log prompt content

---

**Privacy Concerns and Mitigations:**

**1. Tool Arguments**
- **Risk:** May contain passwords, API keys, PII, PCI data, code, queries
- **Default behavior:** Truncate to `max_content_capture_size` (default: 1024 bytes)
- **Optional:** Pattern-based redaction (`enable_content_redaction = T`)
  - Credit card patterns: `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
  - SSN patterns: `\d{3}-\d{2}-\d{4}`
  - Email patterns (configurable): `[\w\.-]+@[\w\.-]+`
- **Forensics:** Hash full content for later correlation if needed
- **Configuration:** Can disable logging entirely per tool via policy

**2. Resource Content**
- **Risk:** Potentially large proprietary data (source code, configs, database contents)
- **Default behavior:** Log URI only, NOT content
- **Optional:** `capture_resource_preview = T` enables truncated preview
- **Always log:** `resource_content_size` for volumetric analysis
- **Forensics:** Resource URI + timestamp allows reconstruction if source preserved
- **Note:** In TLSI/TLS termination scenarios, full content is already visible to security team

**3. Resource URIs**
- **Risk:** URIs themselves may reveal architecture (`database://prod-mysql-01/users`)
- **Default behavior:** Log full URI
- **Optional:** URI anonymization for specific patterns
- **Use case:** Track access patterns without revealing exact backend systems

**4. Prompt Content**
- **Risk:** Prompt templates may reveal business processes or proprietary workflows
- **Default behavior:** Log prompt name only
- **Optional:** `capture_prompt_content = T` enables full template logging
- **Typical use:** Understanding MCP interactions, not security monitoring
- **Note:** Prompt templates are server-defined and relatively static

**5. Prompt Arguments**
- **Risk:** User-provided values may contain sensitive queries or data
- **Default behavior:** Truncate and apply redaction (same as tool arguments)
- **Example:** `git-commit` prompt with argument `changes: "Fixed auth bypass bug"`

**6. Sampling Prompts (Highest Risk)**
- **Risk:** Full context sent to LLM - may contain any user input
- **Default behavior:** Do NOT log prompt content
- **Optional:** `capture_sampling_prompts = T` (use with extreme caution)
- **Metadata always logged:** Model name, token counts, timing
- **Use case for enabling:** Debugging MCP flows, not production security monitoring

---

**Configuration Options:**

```zeek
# Default: Security-focused (minimal sensitive data capture)
@load base/protocols/mcp

# Option 1: Enable full MCP interaction visibility (development/debugging)
redef MCP::capture_prompt_content = T;
redef MCP::capture_resource_preview = T;
redef MCP::capture_sampling_prompts = F;  # Still too risky
redef MCP::max_content_capture_size = 4096;

# Option 2: Maximum security (metadata only)
redef MCP::capture_prompt_content = F;
redef MCP::capture_resource_preview = F;
redef MCP::capture_sampling_prompts = F;
redef MCP::max_content_capture_size = 256;  # Very short truncation

# Option 3: Research/understanding MCP (use on non-production traffic)
redef MCP::capture_prompt_content = T;
redef MCP::capture_resource_preview = T;
redef MCP::capture_sampling_prompts = T;  # ⚠️ HIGH RISK
redef MCP::max_content_capture_size = 0;  # Unlimited
redef MCP::enable_content_redaction = T;  # Still apply pattern redaction
```

**Recommended Settings by Use Case:**

| Use Case | capture_prompt | capture_resource | capture_sampling | max_size |
|----------|---------------|------------------|------------------|----------|
| Production Security | F | F | F | 512 |
| MCP Debugging | T | T | F | 2048 |
| Research (non-prod) | T | T | T | 4096 |
| Compliance Audit | F | F | F | 256 |

---

**Security Monitoring Use Cases:**

**1. Anomaly Detection**
- **Unusual tool frequency:** Detect tool spam or enumeration attempts
- **Resource access patterns:** Identify unauthorized data access
- **Error rate spikes:** Flag authentication failures or permission denials
- **Time-based anomalies:** Tool calls outside business hours
- **Volumetric:** Large resource reads (potential exfiltration)

**2. Access Control Monitoring**
- **Tool authorization matrix:** Track which clients use which tools
- **Resource access tracking:** Map client → resource URI patterns
- **Privilege escalation:** Detect access to admin-level tools
- **Cross-user correlation:** Link multiple MCP sessions to same client

**3. Data Exfiltration Detection**
- **Large resource reads:** `resource_content_size > threshold`
- **Repeated tool calls:** Same tool with varying arguments (enumeration)
- **High-frequency sampling:** Potential data extraction via LLM
- **SSE stream analysis:** Long-running streams with high byte counts

**4. Compliance and Audit**
- **Tool execution audit trail:** Who called what tool, when, with what arguments
- **Resource access logs:** Prove (or disprove) access to sensitive resources
- **Model usage tracking:** Which AI models accessed what data
- **Retention:** MCP logs as evidence for incident investigation

**5. AI-Specific Security Risks**
- **Prompt injection detection:** Unusual characters or patterns in arguments
- **Tool chaining attacks:** Sequences of tools that together achieve malicious goal
- **Context poisoning:** Resources containing malicious instructions
- **Model jailbreaking attempts:** Sampling prompts with known jailbreak patterns

---

**Sensitive Data Handling Best Practices:**

1. **Start conservative:** Use default settings (minimal capture) in production
2. **Enable selectively:** Turn on content capture only for debugging specific issues
3. **Apply redaction:** Always enable `enable_content_redaction` if capturing content
4. **Audit access:** Restrict access to MCP logs (they may contain sensitive data)
5. **Retention policies:** Shorter retention for logs with content capture enabled
6. **Test patterns:** Validate redaction patterns with sample data before production
7. **Document decisions:** Record why content capture was enabled and when to disable

**Example Redaction Implementation:**

```zeek
function redact_sensitive(content: string): string
{
    local result = content;

    # Credit card numbers
    result = sub(result, /\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/, "[REDACTED:CC]");

    # SSN
    result = sub(result, /\d{3}-\d{2}-\d{4}/, "[REDACTED:SSN]");

    # Email addresses (optional)
    if ( MCP::redact_email_addresses )
        result = sub(result, /[\w\.-]+@[\w\.-]+/, "[REDACTED:EMAIL]");

    # AWS keys
    result = sub(result, /AKIA[0-9A-Z]{16}/, "[REDACTED:AWS_KEY]");

    # Passwords in URLs
    result = sub(result, /:[^:@]+@/, ":[REDACTED:PASS]@");

    return result;
}
```

---

## Conclusion

This specification outlines a comprehensive, phased approach to bringing MCP support to Zeek:

1. **Modernize HTTP:** Migrate to Spicy for maintainability and extensibility
2. **Enable SSE:** Add Server-Sent Events parsing for streaming protocols
3. **Implement MCP:** Build MCP-specific analyzer on top of HTTP/SSE foundation
4. **Ensure Quality:** Rigorous testing at every phase

The result will be:
- **For Security Teams:** Visibility into AI assistant traffic
- **For Zeek Community:** Modern, maintainable HTTP analyzer
- **For Developers:** Foundation for other streaming protocols

**Next Steps:**

1. Review this specification with Zeek core team
2. Validate technical approach (Spicy capabilities, performance)
3. Create GitHub project/issues for tracking
4. Begin Phase 1: Spicy HTTP Grammar development

**Questions? Contact:**
- Zeek Slack: #development
- Zeek Mailing List: zeek@zeek.org
- GitHub Discussions: zeek/zeek

---

**Document Version History:**

- v1.2 (2025-11-26): Added comprehensive performance optimization section for high-visibility deployments (TLSI proxies, TLS termination, dev environments), including decompression plugin design, early MCP detection, and 6 major performance risk mitigations. Clarified terminology from "B&I" to "TLSI/TLS termination" for broader accuracy.
- v1.1 (2025-11-26): Added optional content capture fields and comprehensive privacy/security guidance
- v1.0 (2025-11-26): Initial specification
