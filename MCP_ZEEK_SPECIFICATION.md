# Zeek MCP Protocol Support: Specification and Implementation Plan

**Version:** 1.0
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
11. [References](#references)

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
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│   │   HTTP   │  │   DNS    │  │   SSL    │  │
│   │ (C/C++)  │  │ (C/C++)  │  │ (Spicy)  │  │
│   └──────────┘  └──────────┘  └──────────┘  │
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
│  (AI Assistant) │                            │ (Data Source)   │
└─────────────────┘                            └─────────────────┘
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

        ## For sampling: model name
        model: string &log &optional;

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

**mcp.log - Notification (No Response):**
```
ts=1732600000.500000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=2 jsonrpc_version=2.0 method=NOTIFICATIONS_PROGRESS
method_name=notifications/progress request_size=256 is_notification=T has_response=F
progress_token=task-abc123 progress_value=50 progress_total=100 timed_out=F
```

**mcp.log - Error Response:**
```
ts=1732600000.750000 uid=CHhAvVGS1DHFjwGM9 id=[192.168.1.100:54321 -> 10.0.1.50:443]
trans_depth=3 jsonrpc_version=2.0 msg_id=43 method=RESOURCES_READ
method_name=resources/read resource_uri=file:///etc/passwd request_size=512
is_notification=F has_response=T response_status=error error_code=-32001
error_message="Access denied to resource" response_size=128 response_time=0.050s timed_out=F
```

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

**Benchmarks:**

```bash
# Baseline: Current C++ HTTP
zeek -r large-http-trace.pcap -b base/protocols/http

# New: Spicy HTTP
zeek -r large-http-trace.pcap -b spicy/protocols/http

# Compare: Memory, CPU, throughput
```

**Acceptance Criteria:**

- **Throughput:** >= 90% of C++ version
- **Memory:** <= 110% of C++ version
- **Latency:** < 5% increase in event processing time

### Regression Prevention

**CI/CD Integration:**

- GitHub Actions workflow
- Run full test suite on every PR
- Block merge if tests fail
- Performance regression alerts

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

**Privacy Concerns:**

1. **Tool Arguments:** May contain sensitive data
   - **Mitigation:** Truncate in logs, hash full content
   - **Option:** Disable logging via policy

2. **Resource Content:** Could be proprietary
   - **Mitigation:** Log URIs only, not content
   - **Option:** Allowlist of safe resource patterns

3. **Prompts:** May reveal business logic
   - **Mitigation:** Log prompt names, not content
   - **Option:** Redaction policies

**Security Monitoring:**

1. **Anomaly Detection:**
   - Unusual tool invocation frequency
   - Access to unexpected resources
   - Error rate spikes

2. **Access Control:**
   - Track which clients access which tools
   - Build authorization matrix
   - Alert on violations

3. **Data Exfiltration:**
   - Large resource reads
   - Repeated tool calls (enumeration)
   - SSE stream volume

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

- v1.0 (2025-11-26): Initial specification
