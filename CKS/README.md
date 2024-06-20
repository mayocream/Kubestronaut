# CKS

## Requirements

Reference: [CKS Environment](https://docs.linuxfoundation.org/tc-docs/certification/important-instructions-cks#cks-environment)

- One active monitor (either built in or external)  (NOTE: Dual Monitors are NOT supported).

- The CKS environment is currently running etcd v3.5

- The CKS environment is currently running Kubernetes v1.30

## Training

- [Killer Shell CKS](https://killercoda.com/killer-shell-cks)

[Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/):
- [NodeRestriction](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)
- [AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
  - `apparmor_parser`
  - `aa-status`
- [Audit logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#log-backend)
- [CSR](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user)
  - [openssl](https://kubernetes.io/docs/tasks/administer-cluster/certificates/#openssl)

Notes:

Set client credentials:

```bash
k config set-credentials 60099@internal.users --client-key=60099.key --client-certificate=60099.crt
k config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users
k config get-contexts
k config use-context 60099@internal.users
```


API server:

```bash
- kube-apiserver
- --authorization-mode=Node,RBAC
- --etcd-servers=https://127.0.0.1:2379
- --enable-admission-plugins=NodeRestriction
# Enable audit logs
- --audit-policy-file=/etc/kubernetes/audit-policy/policy.yaml
- --audit-log-path=/etc/kubernetes/audit-logs/audit.log
- --audit-log-maxsize=7
- --audit-log-maxbackup=2
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
