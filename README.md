# Kubestronaut

Hands-on Kubernetes learning resources.

## CKA & CKAD

- [Bookmarks](https://gist.github.com/mayocream/0022fcf2235b5acaedec0333a73b6ea9)
- [Blogpost](https://mayo.rocks/2021/10/cka-ckad-journey/)

## CKS

### Requirements

Reference: [CKS Environment](https://docs.linuxfoundation.org/tc-docs/certification/important-instructions-cks#cks-environment)

- One active monitor (either built in or external)  (NOTE: Dual Monitors are NOT supported).
- The CKS environment is currently running etcd v3.5
- The CKS environment is currently running Kubernetes v1.30

### Training

- [Killer Shell CKS](https://killercoda.com/killer-shell-cks)

### Simulator

- [killer.sh](https://killer.sh/)

### References

#### Pre Setup

- [kubectl Quick Reference](https://kubernetes.io/docs/reference/kubectl/quick-reference/#interacting-with-running-pods)

Shell:

```bash
export do="--dry-run=client -o yaml"    # k create deploy nginx --image=nginx $do
export now="--force --grace-period 0"   # k delete pod x $now
```

#### Basic

Base64:

```bash
echo -n "admin" | base64 -w0
echo -n "YWRtaW4=" | base64 -d
```

Find pod by container id:

```bash
crictl ps -id <container-id>
crictl pods -id <pod-id>
```

#### Falco

- [Supported Fields for Conditions and Outputs](https://falco.org/docs/reference/rules/supported-fields/)
- edit `/etc/falco/falco_rules.local.yaml`
- `cat /opt/course/2/falco.log.dirty | cut -d" " -f 9 > /opt/course/2/falco.log`
- The tool cut will split input into fields using space as the delimiter (-d""). We then only select the 9th field using -f 9.

#### API Server

api-server as static pod: `/etc/kubernetes/manifests/kube-apiserver.yaml`.

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
# expose
- --kubernetes-service-node-port=31000
# CIS benchmark
- --profiling=false
```

#### Pod Security

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)


```yaml
# MODE must be one of `enforce`, `audit`, or `warn`.
# LEVEL must be one of `privileged`, `baseline`, or `restricted`.
pod-security.kubernetes.io/<MODE>: <LEVEL>
```

#### CIS Benchmark

```bash
kube-bench run --targets=master
kube-bench run --targets=node
```

#### Verify Binaries

```bash
sha512sum /usr/bin/kubelet
cat compare | uniq
```

#### Open Policy Agent

```bash
k edit blacklistimages pod-trusted-images
k edit constrainttemplates blacklistimages
```

#### Secure Kubernetes Dashboard

- https://github.com/kubernetes/dashboard/tree/master/docs
- `k -n kubernetes-dashboard get pod,svc`

```bash
k -n kubernetes-dashboard edit deploy kubernetes-dashboard
```

```yaml
  template:
    spec:
      containers:
      - args:
        - --namespace=kubernetes-dashboard
        - --authentication-mode=token        # change or delete, "token" is default
        - --auto-generate-certificates       # add
        #- --enable-skip-login=true          # delete or set to false
        #- --enable-insecure-login           # delete
        image: kubernetesui/dashboard:v2.0.3
        imagePullPolicy: Always
        name: kubernetes-dashboard
```

#### AppArmor

- [AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
  - `apparmor_parser`
  - `aa-status`
- [nodeSelector](https://kubernetes.io/docs/tasks/configure-pod-container/assign-pods-nodes/#create-a-pod-that-gets-scheduled-to-your-chosen-node)


#### gVisor

- [RuntimeClasses](https://kubernetes.io/docs/concepts/containers/runtime-class)

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

Pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: gvisor-test
  name: gvisor-test
  namespace: team-purple
spec:
  nodeName: cluster1-node2 # add
  runtimeClassName: gvisor   # add
  containers:
  - image: nginx:1.19.2
    name: gvisor-test
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
status: {}
```

#### ETCD

- [etcdctl](https://etcd.io/docs/v3.5/op-guide/etcdctl/)

```bash
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd
ETCDCTL_API=3 etcdctl \
--cert /etc/kubernetes/pki/apiserver-etcd-client.crt \
--key /etc/kubernetes/pki/apiserver-etcd-client.key \
--cacert /etc/kubernetes/pki/etcd/ca.crt get /registry/{type}/{namespace}/{name}
```

#### Permission escalation

```bash
k -n restricted get role,rolebinding,clusterrole,clusterrolebinding
k -n restricted get secrets -o yaml

k -n restricted get pod -o yaml | grep -i secret

# via volume
k -n restricted exec pod1-fd5d64b9c-pcx6q -- cat /etc/secret-volume/password

# via env
k -n restricted exec pod2-6494f7699b-4hks5 -- env | grep PASS

# via API
k -n restricted exec -it pod3-748b48594-24s76 -- sh
curl https://kubernetes.default/api/v1/namespaces/restricted/secrets -H "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token)" -k
```

#### Network Policies

- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-deny
  namespace: metadata-access
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 192.168.100.21/32
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-allow
  namespace: metadata-access
spec:
  podSelector:
    matchLabels:
      role: metadata-accessor
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 192.168.100.21/32
```

#### Syscall

```bash
strace -p <pid>
```

#### Ingress TLS

```bash
k -n <namespace> create secret tls tls-secret --key tls.key --cert tls.crt
```

#### Audit log

- [Audit log](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

```yaml
# /etc/kubernetes/audit/policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:

# log Secret resources audits, level Metadata
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets"]

# log node related audits, level RequestResponse
- level: RequestResponse
  userGroups: ["system:nodes"]

# for everything else don't log anything
- level: None
```

#### Other

[Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/):
- [NodeRestriction](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)
- [Audit logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#log-backend)
- [CSR](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user)
  - [openssl](https://kubernetes.io/docs/tasks/administer-cluster/certificates/#openssl)
- [EncryptionConfiguration](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#understanding-the-encryption-at-rest-configuration)
  - `kubectl -n one get secrets -o json | kubectl replace -f -` recreate secrets
- [ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)

Notes:

Set client credentials:

```bash
k config set-credentials 60099@internal.users --client-key=60099.key --client-certificate=60099.crt
k config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users
k config get-contexts
k config use-context 60099@internal.users
```

Logs:

```bash
crictl logs <container-id>
cat /var/log/pods/<pod-id>/<container-name>/0.log
```

Common:

```bash
watch crictl ps

# We can contact the Apiserver as the Kubelet by using the Kubelet kubeconfig
export KUBECONFIG=/etc/kubernetes/kubelet.conf
```

Docker:

```bash
# shared PID namespace
docker run --name nginx -d --pid=container:app1 nginx
```

