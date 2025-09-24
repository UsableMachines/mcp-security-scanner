# MicroVM Sandbox Integration Research

## Project Overview

This document outlines the research and experimental integration of Firecracker microVMs as a sandbox option for the MCP Security Scanner, managed through Flintlock and deployed on K3s for development environments.

### Core Concept

Replace the current Docker-based sandbox with Firecracker microVMs to provide:
- **Enhanced Security Isolation**: True hardware-level isolation vs container isolation
- **Consistent Performance**: Predictable resource allocation and performance characteristics
- **Lightweight Virtualization**: Fast boot times (~125ms) with minimal overhead
- **Kubernetes-Native Management**: Leverage existing orchestration patterns

### Technology Stack

1. **Firecracker**: AWS's microVM technology for lightweight virtualization
2. **Flintlock**: Liquid Metal's service for managing Firecracker microVMs
3. **K3s**: Lightweight Kubernetes for development environments

## Technology Context

### Firecracker Overview

**What it is**: Secure, fast microVMs for serverless computing
- **Boot Time**: ~125ms cold start
- **Memory Overhead**: ~5MB per microVM
- **Isolation**: Hardware-level via KVM
- **API**: RESTful HTTP API for VM lifecycle management

**Key Features**:
- OCI image support for VM root filesystems
- Device mapper snapshotter for efficient storage
- Built-in security via KVM and seccomp-BPF
- Network isolation through CNI plugins

**Installation Requirements**:
```bash
# System Requirements Check
#!/bin/bash
[ "$(uname) $(uname -m)" = "Linux x86_64" ] || echo "ERROR: Requires Linux x86_64"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || echo "ERROR: /dev/kvm inaccessible"
(( $(uname -r | cut -d. -f1)*1000 + $(uname -r | cut -d. -f2) >= 4014 )) || echo "ERROR: Kernel too old"
```

### Flintlock Overview

**What it is**: gRPC/HTTP service for Firecracker microVM lifecycle management
- **API-Driven**: Create, delete, start, stop, pause microVMs
- **OCI Integration**: Uses OCI images for volumes, kernels, initrd
- **Cloud-init Support**: Metadata configuration via cloud-init/ignition
- **Monitoring**: Prometheus metrics integration

**Architecture**:
- Host-based service managing local microVMs
- gRPC API for programmatic control
- Integration with Cluster API Provider MicroVM (CAPMVM)
- Support for both Firecracker and Cloud Hypervisor

**Primary Use Case**: Creating microVMs as Kubernetes nodes in virtualized clusters

### K3s Overview

**What it is**: Lightweight, production-ready Kubernetes distribution
- **Single Binary**: <100MB, includes containerd, CoreDNS, CNI
- **Low Resources**: Optimized for edge and development environments
- **Easy Installation**: Simple curl script installation
- **Full Compatibility**: Certified Kubernetes distribution

**Quick Setup**:
```bash
# Server Installation
curl -sfL https://get.k3s.io | sh -

# Agent Installation
curl -sfL https://get.k3s.io | K3S_URL=https://myserver:6443 K3S_TOKEN=mynodetoken sh -
```

## Proposed Architecture

### High-Level Design

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   MCP Scanner   │───▶│   Flintlock API  │───▶│  Firecracker VMs    │
│                 │    │                  │    │  (Sandbox Envs)    │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
         │                       │                        │
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   K3s Cluster   │    │   Host Machine   │    │   Security Analysis │
│   (Dev Setup)   │    │   (Flintlock)    │    │   Results           │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
```

### Integration Points

#### 1. Scanner to Flintlock Integration
- Replace `DockerProvider` with `FlintlockProvider` in `SandboxManager`
- Implement gRPC client for Flintlock API
- Handle microVM lifecycle: create → configure → execute → destroy

#### 2. MCP Execution Environment
- Create base microVM image with MCP runtime dependencies
- Use cloud-init for dynamic MCP server configuration
- Network isolation with controlled egress monitoring

#### 3. K3s Development Deployment
- Deploy Flintlock as K3s DaemonSet or StatefulSet
- Use K3s for development environment orchestration
- Scale to production K8s later if needed

## Implementation Plan

### Phase 1: Research & Setup (Weeks 1-2)
1. **Environment Setup**
   - Install Firecracker, Flintlock, K3s on development machine
   - Verify system requirements and KVM access
   - Create basic microVM test cases

2. **Base Image Creation**
   - Build OCI-compatible base image with:
     - Node.js runtime for MCP servers
     - Common dependencies (Python, etc.)
     - Security monitoring tools
     - Network utilities for analysis

3. **Flintlock Integration Prototype**
   - Implement basic `FlintlockProvider` class
   - Create/destroy microVM lifecycle
   - Basic networking and storage configuration

### Phase 2: Core Integration (Weeks 3-4)
1. **Provider Implementation**
   - Complete `FlintlockProvider` with full SandboxManager interface
   - Implement resource management and cleanup
   - Add monitoring and metrics collection

2. **MCP Runtime Environment**
   - Cloud-init templates for MCP server configuration
   - Dynamic server deployment and execution
   - Results collection from microVM environments

3. **K3s Deployment**
   - Containerize Flintlock service
   - K3s manifests for development deployment
   - Basic CI/CD integration

### Phase 3: Testing & Optimization (Weeks 5-6)
1. **Performance Testing**
   - Boot time vs Docker containers
   - Resource utilization comparison
   - Concurrent microVM limits

2. **Security Validation**
   - Isolation verification
   - Network security testing
   - Privilege escalation prevention

3. **Integration Testing**
   - End-to-end MCP scanning workflows
   - Error handling and recovery
   - Production readiness assessment

## Technical Challenges & Solutions

### Challenge 1: Control Plane Complexity
**Problem**: Flintlock is designed for Kubernetes node creation, not ephemeral sandbox execution
**Potential Solutions**:
- Custom control plane wrapper around Flintlock API
- Extend Flintlock with sandbox-specific functionality
- Build lightweight orchestrator for microVM lifecycle

**Implementation Approach**:
```typescript
class MicroVMController {
  private flintlockClient: FlintlockClient;
  private vmPool: Map<string, MicroVMInstance>;

  async createSandbox(mcpConfig: MCPConfig): Promise<SandboxInstance> {
    // 1. Get or create microVM from pool
    // 2. Configure via cloud-init
    // 3. Start MCP server
    // 4. Return execution interface
  }
}
```

### Challenge 2: Image Management
**Problem**: Efficient base image creation and distribution
**Solutions**:
- Layer-based image building with common dependencies
- Registry integration for image distribution
- Snapshot-based rapid deployment

### Challenge 3: Networking & Monitoring
**Problem**: Network isolation while enabling monitoring
**Solutions**:
- CNI plugin configuration for controlled networking
- Side-car monitoring containers in microVMs
- Flintlock metrics integration with existing Prometheus setup

### Challenge 4: Resource Management
**Problem**: Optimal resource allocation and cleanup
**Solutions**:
- Pool-based microVM management for reuse
- Automated cleanup with timeout mechanisms
- Resource quotas and limits enforcement

### Challenge 5: Development Complexity
**Problem**: More complex than Docker for development
**Solutions**:
- Feature flag for Docker/microVM toggle
- Comprehensive documentation and tooling
- Automated development environment setup

## Performance Considerations

### Expected Benefits
- **Isolation**: True hardware isolation vs container namespaces
- **Security**: Kernel-level isolation prevents container escapes
- **Consistency**: Predictable performance characteristics
- **Scalability**: Lightweight footprint allows higher density

### Expected Tradeoffs
- **Boot Time**: ~125ms vs ~100ms for containers
- **Memory Overhead**: ~5MB per microVM vs minimal container overhead
- **Complexity**: Additional orchestration layer vs simple Docker
- **Development**: Steeper learning curve and setup

### Benchmarking Plan
1. **Boot Time Comparison**: microVM vs Docker container startup
2. **Resource Usage**: Memory, CPU, storage overhead analysis
3. **Execution Performance**: MCP server runtime performance
4. **Concurrency Limits**: Maximum parallel sandbox instances
5. **Network Performance**: I/O throughput and latency

## Configuration Structure

### Environment Variables
```bash
# Flintlock Configuration
FLINTLOCK_API_ENDPOINT=http://localhost:9090
FLINTLOCK_GRPC_ENDPOINT=localhost:9091
MICROVM_BASE_IMAGE=ghcr.io/kindo/mcp-sandbox:latest
MICROVM_KERNEL_IMAGE=ghcr.io/kindo/vmlinux:5.10
MICROVM_MEMORY_MB=512
MICROVM_CPU_COUNT=1

# K3s Development Setup
K3S_KUBECONFIG=/etc/rancher/k3s/k3s.yaml
FLINTLOCK_NAMESPACE=mcp-sandbox

# Feature Flags
SANDBOX_PROVIDER=microvm  # docker|microvm
ENABLE_MICROVM_POOL=true
MICROVM_POOL_SIZE=5
```

### Flintlock Service Configuration
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: flintlock-config
  namespace: mcp-sandbox
data:
  config.yaml: |
    grpc_endpoint: "0.0.0.0:9091"
    http_endpoint: "0.0.0.0:9090"
    parent_iface: "eth0"
    bridge_name: "flintlock0"
    firecracker:
      binary_path: "/usr/local/bin/firecracker"
      kernel_image_path: "/var/lib/flintlock/kernel/vmlinux"
      kernel_args: "console=ttyS0 reboot=k panic=1 pci=off"
```

## Risk Assessment

### High Risk
1. **Development Complexity**: Significant increase in setup and maintenance complexity
2. **Performance Unknowns**: Unclear if benefits outweigh overhead for our use case
3. **Ecosystem Maturity**: Flintlock is relatively young, potential stability issues

### Medium Risk
1. **Resource Requirements**: Higher memory/CPU usage than Docker
2. **Debugging Difficulty**: More complex troubleshooting vs containers
3. **CI/CD Integration**: Additional complexity in build/test pipelines

### Low Risk
1. **Security Benefits**: Well-established Firecracker security model
2. **Community Support**: Strong backing from AWS and CNCF community
3. **Migration Path**: Can implement alongside Docker with feature flags

## Success Metrics

### Technical Metrics
- **Boot Time**: Target <200ms end-to-end sandbox creation
- **Resource Efficiency**: <10MB average memory overhead per sandbox
- **Security**: Zero privilege escalation or container escapes
- **Reliability**: >99.9% successful sandbox creation rate

### Development Metrics
- **Setup Time**: <30 minutes for new developer environment
- **Debugging**: Equivalent troubleshooting experience to Docker
- **Maintenance**: Minimal additional operational overhead

## Next Steps

1. **Immediate Actions**:
   - Set up development environment with Firecracker + Flintlock + K3s
   - Create proof-of-concept microVM sandbox provider
   - Basic performance and security testing

2. **Decision Points** (Week 2):
   - Go/no-go based on initial complexity assessment
   - Performance benchmarking results
   - Resource requirement analysis

3. **Implementation Phases**:
   - Phase 1: Prototype and validation
   - Phase 2: Full integration with feature flags
   - Phase 3: Production deployment consideration

## References

- [Firecracker Documentation](https://github.com/firecracker-microvm/firecracker)
- [Firecracker-Containerd](https://github.com/firecracker-microvm/firecracker-containerd)
- [Flintlock Repository](https://github.com/liquidmetal-dev/flintlock)
- [K3s Documentation](https://docs.k3s.io/)
- [Cluster API Provider MicroVM](https://github.com/k3s-io/cluster-api-k3s)

---

*Document Version: 1.0*
*Last Updated: 2024-09-23*
*Status: Research & Planning Phase*