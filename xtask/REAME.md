# xtask

Key features:

* Flow-based analysis, not per-packet
* Supports IPv4 and IPv6 with separate eBPF programs
* High-performance: eBPF in kernel space, minimal user-space overhead
* Extensible for ML or IDS systems

## `cargo xtask` Workflow for eBPF Compilation

In this project, the `xtask` crate is used to manage custom build tasks, such as compiling eBPF programs. The workflow for running a command like `cargo xtask ebpf-ipv4` is as follows:

```txt
cargo xtask ebpf-ipv4
   ↓
cargo run -p xtask -- ebpf-ipv4
   ↓
xtask/src/main.rs
   ↓
Parse the command `ebpf-ipv4`
   ↓
Call `build_ebpf::build_ebpf(opts, "ebpf-ipv4")`
   ↓
Generate the eBPF `.o` file
```

## Darkflow Traffic Processing Architecture

The traffic processing in the **Darkflow** project follows this architecture:

```txt
Network Packet
      ↓
Network Interface / Kernel Network Stack
      ↓
eBPF Program (written with Aya, running in kernel space)
      ↓
eBPF Maps (shared memory between kernel and user space)
      ↓
User-space Rust Program (`darkflow run`)
      ↓
Feature Extraction / Traffic Analysis / CSV Output
```

### 1. Aya’s Role

Aya handles three main responsibilities:

### 1.1 Writing eBPF Programs (Kernel Space)

```rust
#[xdp]
pub fn darkflow_xdp(ctx: XdpContext) -> u32 {
    let packet = ctx.data();
    // Parse IP / TCP / UDP
    // Update flow map
    XDP_PASS
}
```

* Runs **inside the kernel**
* Restrictions:

  * No heap allocation
  * No standard library (`no_std`)
  * No syscalls
* Allowed:

  * Parse packets
  * Update eBPF maps
  * Decide XDP/TC action

### 1.2 Defining eBPF Maps

```rust
#[map]
static mut FLOW_TABLE: HashMap<FlowKey, FlowStats> =
    HashMap::with_max_entries(1024, 0);
```

* eBPF maps serve as a **bridge between kernel and user space**:

  * Kernel writes: update flow statistics on each packet
  * User-space reads: collect flow stats periodically for analysis

### 1.3 Loading and Managing eBPF Programs (User Space)

```rust
let mut bpf = Bpf::load_file("ebpf-ipv4.o")?;
let program: &mut Xdp = bpf.program_mut("darkflow_xdp")?.try_into()?;
program.load()?;
program.attach("eth0", XdpFlags::default())?;
```

* Loads eBPF bytecode (`.o`) into kernel
* Attaches to a network interface (e.g., `eth0`)
* All traffic going through this interface will trigger the eBPF program

### 2. Flow of a Single Packet

1. Packet enters the network interface
2. eBPF program triggers (XDP or TC)
3. Kernel-space program:

   * Parses Ethernet → IP → TCP/UDP headers
   * Builds a `FlowKey` (src IP, dst IP, src port, dst port, protocol)
   * Updates `FLOW_TABLE`:

     * New flow → insert
     * Existing flow → update counters
4. eBPF program returns `XDP_PASS` (or other action)
5. Kernel forwards the packet normally

> Note: The packet is **observed, not blocked or modified**.

### 3. User-Space Flow Analysis

The Rust program (`darkflow run`) periodically:

1. Reads the `FLOW_TABLE` map
2. Checks for flow expiration:

   * `idle_timeout`: max idle time for a flow
   * `active_timeout`: max lifetime for a flow
   * `expiration_check_interval`: interval to scan the table
3. Exports features such as:

   * Flow duration, packet count, byte count, average packet length, TCP flags, etc.
4. Outputs to CSV, prints to console, or feeds downstream ML models
