# CKS

## Requirements

Reference: [CKS Environment](https://docs.linuxfoundation.org/tc-docs/certification/important-instructions-cks#cks-environment)

- One active monitor (either built in or external)  (NOTE: Dual Monitors are NOT supported).

- The CKS environment is currently running etcd v3.5

- The CKS environment is currently running Kubernetes v1.30

## Training

- [Killer Shell CKS](https://killercoda.com/killer-shell-cks)

## [1. Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)

- [NodeRestriction](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)


Notes:

API server:

```bash
- kube-apiserver
- --authorization-mode=Node,RBAC
- --etcd-servers=https://127.0.0.1:2379
- --enable-admission-plugins=NodeRestriction
```

Logs:

```bash
crictl logs <container-id>
cat /var/log/pods/<pod-id>/<container-name>/0.log
```

Manifests:

```bash
cat /etc/kubernetes/manifests/kube-apiserver.yaml
```

Common:

```bash
watch crictl ps

# We can contact the Apiserver as the Kubelet by using the Kubelet kubeconfig
export KUBECONFIG=/etc/kubernetes/kubelet.conf
```


## Simulator

- [killer.sh](https://killer.sh/)
