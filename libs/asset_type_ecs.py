#!/usr/bin/env python
"""
Asset types ECS class (ultra-minimal security output + red highlights)

Displayed fields (discover):
- Cluster/Service (as the asset key)
- ExposureDNS (only if an internet-facing LB is attached)
- PrivateIP (the target IP(s) currently registered in the target group(s) of the service)
- ContainerPrivilege (one-line: "privileged" | "root" | "none" | "privileged+root")
    -> highlighted in red when != "none"
- AdminActions (ONLY if non-empty): ["*"] or ["s3", "s3-object-lambda", ...]
    -> highlighted in red

Notes:
- "AdminActions" here means: either "*" (full admin) OR service-level admin (e.g. 's3:*' -> 's3').
- We deliberately do NOT print ALL Actions to stay concise.
- We keep `security_groups` as an empty dict to avoid breaking existing audit/draw flows
  (Patterns expects `.security_groups.items()`).
"""

from __future__ import annotations

import botocore
from datetime import datetime, timezone

from .asset_type import AssetType
from .tools import get_network, log_me, search_filter_in


def _chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _short_arn_tail(arn: str) -> str:
    if not arn:
        return ""
    return arn.split("/")[-1]


def _parse_ecr_image(image: str):
    """
    Parse ECR image reference.
    Returns (registry_id, repository, image_tag) or (None, None, None) if not ECR/tagged.
    """
    if not image or ".dkr.ecr." not in image or ".amazonaws.com/" not in image:
        return None, None, None
    try:
        registry = image.split(".dkr.ecr.")[0]
        repo_and_tag = image.split(".amazonaws.com/", 1)[1]
        if ":" not in repo_and_tag:
            return registry, repo_and_tag, None
        repository, tag = repo_and_tag.rsplit(":", 1)
        return registry, repository, tag
    except Exception:
        return None, None, None


def _sg_has_public_ingress(sg_id: str, sg_raw: list[dict]) -> bool:
    """
    Returns True if the security group allows ingress from 0.0.0.0/0 or ::/0.
    """
    if not sg_id:
        return False
    try:
        for sg in sg_raw:
            if sg.get("GroupId") != sg_id:
                continue
            for ip_perm in sg.get("IpPermissions", []) or []:
                for cidr in ip_perm.get("IpRanges", []) or []:
                    if cidr.get("CidrIp") == "0.0.0.0/0":
                        return True
                for cidr6 in ip_perm.get("Ipv6Ranges", []) or []:
                    if cidr6.get("CidrIpv6") == "::/0":
                        return True
    except Exception:
        return False
    return False


def _extract_allow_actions_from_policy_doc(policy_doc: dict) -> set[str]:
    """
    Extract all Allowed Actions from a policy document (managed or inline).
    Best-effort: ignores Deny and conditions.
    """
    actions: set[str] = set()
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for st in stmts:
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue
        act = st.get("Action", [])
        if isinstance(act, str):
            actions.add(act)
        elif isinstance(act, list):
            for a in act:
                if isinstance(a, str):
                    actions.add(a)
    return actions


def _admin_actions_from_actions(actions: set[str]) -> set[str]:
    """
    Convert raw allowed actions into AWS-Tower-like "Admin actions" buckets:
    - If '*' is present -> {'*'}
    - Else if '<service>:*' present -> {'service'}  (e.g. 's3:*' -> 's3')
    - Else empty
    """
    if "*" in actions:
        return {"*"}
    admins: set[str] = set()
    for a in actions:
        if not isinstance(a, str):
            continue
        if a.endswith(":*") and ":" in a:
            admins.add(a.split(":", 1)[0])
    return admins


def _get_role_allowed_actions(iam_client, role_arn: str) -> set[str]:
    """
    Fetch allowed actions for a role:
    - Attached managed policies (get policy default version doc)
    - Inline policies (get role policy doc)
    Returns a set of allowed actions (best-effort).
    """
    if not role_arn or role_arn == "none":
        return set()

    role_name = role_arn.split("/")[-1]
    if not role_name:
        return set()

    allowed: set[str] = set()

    # Inline policies
    try:
        paginator = iam_client.get_paginator("list_role_policies")
        policy_names: list[str] = []
        for page in paginator.paginate(RoleName=role_name):
            policy_names.extend(page.get("PolicyNames", []) or [])
        for pol_name in policy_names:
            try:
                resp = iam_client.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                doc = resp.get("PolicyDocument") or {}
                allowed |= _extract_allow_actions_from_policy_doc(doc)
            except botocore.exceptions.ClientError:
                continue
    except botocore.exceptions.ClientError:
        pass

    # Managed policies
    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        attached = []
        for page in paginator.paginate(RoleName=role_name):
            attached.extend(page.get("AttachedPolicies", []) or [])

        for pol in attached:
            pol_arn = pol.get("PolicyArn")
            if not pol_arn:
                continue
            try:
                pol_meta = iam_client.get_policy(PolicyArn=pol_arn).get("Policy") or {}
                default_ver = pol_meta.get("DefaultVersionId")
                if not default_ver:
                    continue
                ver = iam_client.get_policy_version(PolicyArn=pol_arn, VersionId=default_ver)
                doc = (ver.get("PolicyVersion") or {}).get("Document") or {}
                allowed |= _extract_allow_actions_from_policy_doc(doc)
            except botocore.exceptions.ClientError:
                continue
    except botocore.exceptions.ClientError:
        pass

    return allowed


class ECS(AssetType):
    """
    ECS service asset (minimal).
    """

    def __init__(self, name: str, public: bool = False):
        super().__init__("ECS", name, public=public)

        self.ecs_cluster = ""
        self.service_name = ""

        self.exposure_dns = ""             # only for internet-facing LB
        self.exposure_healthy_targets = False
        self.exposure_public_ingress = False
        self.public_ip_assigned = False
        self.task_public_ingress = False
        self.private_ips: list[str] = []   # TG target IPs
        self.container_privilege = "none"  # privileged|root|none|privileged+root
        self.admin_actions: list[str] = []  # printed only if non-empty
        self.exposure_type = ""            # internet-facing | internal
        self.network_mode = ""             # awsvpc | host | bridge | none
        self.execute_command_enabled = False
        self.exposed_ports: list[int] = []
        self.image = ""
        self.image_age_days = None
        self.secrets_count = 0
        self.container_insights = ""
        self.risk_score = 0

        # keep to not break audit/draw
        self.security_groups = {}

    def _ensure_backcompat(self):
        for attr, default in (
            ("ecs_cluster", ""),
            ("service_name", ""),
            ("exposure_dns", ""),
            ("exposure_healthy_targets", False),
            ("exposure_public_ingress", False),
            ("public_ip_assigned", False),
            ("task_public_ingress", False),
            ("private_ips", []),
            ("container_privilege", "none"),
            ("admin_actions", []),
            ("exposure_type", ""),
            ("network_mode", ""),
            ("execute_command_enabled", False),
            ("exposed_ports", []),
            ("image", ""),
            ("image_age_days", None),
            ("secrets_count", 0),
            ("container_insights", ""),
            ("risk_score", 0),
        ):
            if not hasattr(self, attr):
                setattr(self, attr, default)
        if not hasattr(self, "security_groups") or isinstance(self.security_groups, list):
            self.security_groups = {}

        # Back-compat / rules.yaml expected attribute names
        if not hasattr(self, "ContainerPrivilege"):
            self.ContainerPrivilege = self.container_privilege
        if not hasattr(self, "ExposureDNS"):
            self.ExposureDNS = self.exposure_dns
        if not hasattr(self, "ExposureHealthyTargets"):
            self.ExposureHealthyTargets = str(self.exposure_healthy_targets).lower()
        if not hasattr(self, "ExposurePublicIngress"):
            self.ExposurePublicIngress = str(self.exposure_public_ingress).lower()
        if not hasattr(self, "PublicIpAssigned"):
            self.PublicIpAssigned = str(self.public_ip_assigned).lower()
        if not hasattr(self, "TaskPublicIngress"):
            self.TaskPublicIngress = str(self.task_public_ingress).lower()
        if not hasattr(self, "ExposureType"):
            self.ExposureType = self.exposure_type
        if not hasattr(self, "AdminActions"):
            self.AdminActions = self.admin_actions
        if not hasattr(self, "NetworkMode"):
            self.NetworkMode = self.network_mode
        if not hasattr(self, "ExecuteCommandEnabled"):
            self.ExecuteCommandEnabled = str(self.execute_command_enabled).lower()
        if not hasattr(self, "ExposedPorts"):
            self.ExposedPorts = self.exposed_ports
        if not hasattr(self, "Image"):
            self.Image = self.image
        if not hasattr(self, "ImageAgeDays"):
            self.ImageAgeDays = self.image_age_days
        if not hasattr(self, "SecretsCount"):
            self.SecretsCount = self.secrets_count
        if not hasattr(self, "ContainerInsights"):
            self.ContainerInsights = self.container_insights
        if not hasattr(self, "RiskScore"):
            self.RiskScore = self.risk_score

    def cluster_name(self):
        self._ensure_backcompat()
        return self.ecs_cluster or None

    def src_linked_assets(self, assets):
        self._ensure_backcompat()
        result = set()
        if not self.exposure_dns:
            return result
        for asset in assets:
            if asset.get_type() != "ELB":
                continue
            if asset.name == self.exposure_dns or asset.dns_record == self.exposure_dns:
                result.add(asset)
        return result

    def dst_linked_assets(self, assets):
        return set()

    def report(self, report, brief=False, with_fpkey=False):
        self._ensure_backcompat()

        if brief:
            asset_report = self.report_brief()
        else:
            asset_report: dict = {}

            if self.exposure_dns:
                asset_report["ExposureDNS"] = self.exposure_dns

            if self.private_ips:
                asset_report["PrivateIP"] = self.private_ips[0] if len(self.private_ips) == 1 else self.private_ips

            # ContainerPrivilege (red if dangerous)
            if self.container_privilege != "none":
                asset_report["ContainerPrivilege"] = f"[red]{self.container_privilege}[/red]"
            else:
                asset_report["ContainerPrivilege"] = self.container_privilege

            # AdminActions (red if present)
            if self.admin_actions:
                asset_report["AdminActions"] = f"[red]{self.admin_actions}[/red]"

            if self.security_issues:
                self.update_audit_report(asset_report, with_fpkey)

        if "ECS" not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]["ECS"] = {
                self.name: asset_report
            }
            return report

        report[self.location.region][self.location.vpc][self.location.subnet]["ECS"].update(
            {self.name: asset_report}
        )
        return report

    def report_brief(self):
        self._ensure_backcompat()
        pub = "[red]<Public>[/red] " if self.exposure_dns else ""
        ip = self.private_ips[0] if self.private_ips else "-"

        priv = self.container_privilege
        if priv != "none":
            priv = f"[red]{priv}[/red]"

        admin = f" [red]Admin:{','.join(self.admin_actions)}[/red]" if self.admin_actions else ""
        return f"{pub}{self.ecs_cluster}/{self.service_name} {ip} {priv}{admin}{self.display_brief_audit()}"

    def finding_description(self, _):
        self._ensure_backcompat()
        return f"{self.ecs_cluster}/{self.service_name}"


@log_me("Getting ECS raw data...")
def get_raw_data(raw_data, authorizations, boto_session, cache, console):
    """
    Collect:
    - ECS clusters/services/task definitions
    - ELBv2: TG -> targets (private IPs), TG -> LB DNS (internet-facing only)
    - IAM: TaskRole -> AdminActions (['*'] or ['s3', ...]) (best-effort)
    """
    ecs_client = boto_session.client("ecs")
    elbv2_client = boto_session.client("elbv2")
    iam_client = boto_session.client("iam")
    ecr_client = boto_session.client("ecr")

    raw_data["ecs_raw"] = {
        "clusters": [],
        "clusters_desc": {},          # cluster arn -> cluster dict (settings)
        "services_desc": {},          # (cluster arn, service arn) -> service dict
        "taskdefs_desc": {},          # taskdef arn -> taskdef dict
        "targetgroups_desc": {},      # tg arn -> tg dict (LoadBalancerArns)
        "loadbalancers_desc": {},     # lb arn -> lb dict (Scheme/DNSName)
        "tg_targets": {},             # tg arn -> [target ids]
        "tg_target_health": {},       # tg arn -> [target health states]
        "role_admin_actions": {},     # taskRoleArn -> sorted list[str]
        "image_push_dates": {},       # image string -> push datetime
    }

    # list clusters
    try:
        paginator = ecs_client.get_paginator("list_clusters")
        clusters = []
        for page in paginator.paginate():
            clusters.extend(page.get("clusterArns", []))
        raw_data["ecs_raw"]["clusters"] = clusters
    except botocore.exceptions.ClientError:
        authorizations["ecs"] = False
        raw_data["ecs_raw"]["clusters"] = []
        return raw_data, authorizations

    # describe clusters to get settings (containerInsights)
    for batch in _chunks(raw_data["ecs_raw"]["clusters"], 100):
        try:
            desc = ecs_client.describe_clusters(clusters=batch)
            for cl in desc.get("clusters", []) or []:
                raw_data["ecs_raw"]["clusters_desc"][cl.get("clusterArn", "")] = cl
        except botocore.exceptions.ClientError:
            authorizations["ecs"] = False

    for cluster_arn in raw_data["ecs_raw"]["clusters"]:
        # list services
        try:
            paginator = ecs_client.get_paginator("list_services")
            service_arns = []
            for page in paginator.paginate(cluster=cluster_arn):
                service_arns.extend(page.get("serviceArns", []))
        except botocore.exceptions.ClientError:
            authorizations["ecs"] = False
            continue

        # describe services in batches
        for batch in _chunks(service_arns, 10):
            try:
                desc = ecs_client.describe_services(cluster=cluster_arn, services=batch)
            except botocore.exceptions.ClientError:
                authorizations["ecs"] = False
                continue

            for svc in desc.get("services", []) or []:
                svc_arn = svc.get("serviceArn", "")
                raw_data["ecs_raw"]["services_desc"][(cluster_arn, svc_arn)] = svc

                # task definition
                td_arn = svc.get("taskDefinition")
                if td_arn and td_arn not in raw_data["ecs_raw"]["taskdefs_desc"]:
                    try:
                        td_desc = ecs_client.describe_task_definition(taskDefinition=td_arn)
                        raw_data["ecs_raw"]["taskdefs_desc"][td_arn] = td_desc.get("taskDefinition", {}) or {}
                    except botocore.exceptions.ClientError:
                        authorizations["ecs"] = False
                        raw_data["ecs_raw"]["taskdefs_desc"][td_arn] = {}

                # TG + targets + LB DNS
                for lb in svc.get("loadBalancers", []) or []:
                    tg_arn = lb.get("targetGroupArn")
                    if not tg_arn:
                        continue

                    # TG details
                    if tg_arn not in raw_data["ecs_raw"]["targetgroups_desc"]:
                        try:
                            tg_desc = elbv2_client.describe_target_groups(TargetGroupArns=[tg_arn])
                            tgs = tg_desc.get("TargetGroups", []) or []
                            raw_data["ecs_raw"]["targetgroups_desc"][tg_arn] = tgs[0] if tgs else {}
                        except botocore.exceptions.ClientError:
                            authorizations["elb"] = False
                            raw_data["ecs_raw"]["targetgroups_desc"][tg_arn] = {}

                    # TG targets
                    if tg_arn not in raw_data["ecs_raw"]["tg_targets"]:
                        try:
                            th = elbv2_client.describe_target_health(TargetGroupArn=tg_arn)
                            targets = []
                            health_states = []
                            for d in th.get("TargetHealthDescriptions", []) or []:
                                t = d.get("Target") or {}
                                tid = t.get("Id")
                                if tid:
                                    targets.append(tid)
                                health_states.append((d.get("TargetHealth") or {}).get("State") or "")
                            raw_data["ecs_raw"]["tg_targets"][tg_arn] = targets
                            raw_data["ecs_raw"]["tg_target_health"][tg_arn] = health_states
                        except botocore.exceptions.ClientError:
                            authorizations["elb"] = False
                            raw_data["ecs_raw"]["tg_targets"][tg_arn] = []
                            raw_data["ecs_raw"]["tg_target_health"][tg_arn] = []

                    # LB details via TG LoadBalancerArns
                    tg = raw_data["ecs_raw"]["targetgroups_desc"].get(tg_arn, {}) or {}
                    for lb_arn in (tg.get("LoadBalancerArns", []) or []):
                        if lb_arn in raw_data["ecs_raw"]["loadbalancers_desc"]:
                            continue
                        try:
                            lb_desc = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])
                            lbs = lb_desc.get("LoadBalancers", []) or []
                            raw_data["ecs_raw"]["loadbalancers_desc"][lb_arn] = lbs[0] if lbs else {}
                        except botocore.exceptions.ClientError:
                            authorizations["elb"] = False
                            raw_data["ecs_raw"]["loadbalancers_desc"][lb_arn] = {}

                # Role admin actions (task role)
                if td_arn:
                    td = raw_data["ecs_raw"]["taskdefs_desc"].get(td_arn, {}) or {}
                    role_arn = td.get("taskRoleArn") or "none"
                    if role_arn and role_arn != "none" and role_arn not in raw_data["ecs_raw"]["role_admin_actions"]:
                        actions = _get_role_allowed_actions(iam_client, role_arn)
                        admins = _admin_actions_from_actions(actions)
                        raw_data["ecs_raw"]["role_admin_actions"][role_arn] = sorted(admins) if admins else []

    return raw_data, authorizations


@log_me("Scanning ECS...")
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, boto_session, console):
    ecs_raw = raw_data.get("ecs_raw", {}) if raw_data else {}

    services_desc = ecs_raw.get("services_desc", {}) or {}
    taskdefs_desc = ecs_raw.get("taskdefs_desc", {}) or {}
    targetgroups_desc = ecs_raw.get("targetgroups_desc", {}) or {}
    loadbalancers_desc = ecs_raw.get("loadbalancers_desc", {}) or {}
    tg_targets = ecs_raw.get("tg_targets", {}) or {}
    tg_target_health = ecs_raw.get("tg_target_health", {}) or {}
    role_admin_actions = ecs_raw.get("role_admin_actions", {}) or {}

    subnets_raw = raw_data.get("subnets_raw", []) if raw_data else []
    sg_raw = raw_data.get("sg_raw", []) if raw_data else []

    ecr_client = None
    if boto_session is not None:
        try:
            ecr_client = boto_session.client("ecr")
        except Exception:
            ecr_client = None

    for (cluster_arn, service_arn), svc in services_desc.items():
        cluster_name = _short_arn_tail(cluster_arn) or "unknown"
        service_name = svc.get("serviceName") or _short_arn_tail(service_arn) or "unknown"

        cache_key = f"ECS_{cluster_name}_{service_name}"
        ecs_asset = cache.get_asset(cache_key)

        if ecs_asset is not None and ecs_asset.get_type() == "ECS":
            try:
                ecs_asset._ensure_backcompat()
            except Exception:
                pass

        if ecs_asset is None:
            ecs_asset = ECS(name=f"{cluster_name}/{service_name}", public=False)
            ecs_asset.ecs_cluster = cluster_name
            ecs_asset.service_name = service_name

            # Location (needs VPC/subnet to fit AWS Tower's report hierarchy)
            awsvpc = ((svc.get("networkConfiguration") or {}).get("awsvpcConfiguration")) or {}
            subnets = awsvpc.get("subnets", []) or []
            if not subnets:
                cache.save_asset(cache_key, None)
                continue

            try:
                region, vpc, subnet = get_network(subnets[0], subnets_raw)
                ecs_asset.location.region = region
                ecs_asset.location.vpc = vpc
                ecs_asset.location.subnet = subnet
            except Exception:
                cache.save_asset(cache_key, None)
                continue

            # ExposureDNS (internet-facing LB) + PrivateIPs (TG targets)
            exposure_dns = ""
            exposure_type = ""
            exposure_healthy_targets = False
            exposure_public_ingress = False
            private_ips = set()

            for lb in svc.get("loadBalancers", []) or []:
                tg_arn = lb.get("targetGroupArn")
                if not tg_arn:
                    continue

                for tid in (tg_targets.get(tg_arn, []) or []):
                    private_ips.add(tid)
                if not exposure_healthy_targets:
                    for state in (tg_target_health.get(tg_arn, []) or []):
                        if state == "healthy":
                            exposure_healthy_targets = True
                            break

                tg = targetgroups_desc.get(tg_arn, {}) or {}
                for lb_arn in (tg.get("LoadBalancerArns", []) or []):
                    lbd = loadbalancers_desc.get(lb_arn, {}) or {}
                    if (lbd.get("Scheme") == "internet-facing") and lbd.get("DNSName"):
                        exposure_dns = lbd.get("DNSName") or ""
                        exposure_type = "internet-facing"
                        for sg_id in (lbd.get("SecurityGroups") or []):
                            if _sg_has_public_ingress(sg_id, sg_raw):
                                exposure_public_ingress = True
                                break
                        break
                if exposure_dns:
                    break

            ecs_asset.exposure_dns = exposure_dns
            ecs_asset.exposure_type = exposure_type
            ecs_asset.exposure_healthy_targets = exposure_healthy_targets
            ecs_asset.exposure_public_ingress = exposure_public_ingress
            ecs_asset.private_ips = sorted(private_ips)

            # privileged/root line from task definition
            td_arn = svc.get("taskDefinition", "")
            td = taskdefs_desc.get(td_arn, {}) or {}
            container_defs = td.get("containerDefinitions", []) or []

            is_priv = any((c.get("privileged", False) is True) for c in container_defs)

            is_root = False
            if container_defs:
                user = (container_defs[0] or {}).get("user", None)
                is_root = True if (user is None or user in ("", "root", "0")) else False

            if is_priv and is_root:
                ecs_asset.container_privilege = "privileged+root"
            elif is_priv:
                ecs_asset.container_privilege = "privileged"
            elif is_root:
                ecs_asset.container_privilege = "root"
            else:
                ecs_asset.container_privilege = "none"

            ecs_asset.network_mode = td.get("networkMode", "") or ""
            ecs_asset.execute_command_enabled = bool(svc.get("enableExecuteCommand", False))

            # Exposed ports + image + secrets count
            ports = set()
            image = ""
            secrets_count = 0
            for c in container_defs:
                if not image:
                    image = c.get("image", "") or ""
                for pm in (c.get("portMappings") or []):
                    port_val = pm.get("containerPort")
                    if port_val is not None:
                        ports.add(port_val)
                secrets_count += len(c.get("secrets") or [])
                secrets_count += len(c.get("environment") or [])
            ecs_asset.exposed_ports = sorted(ports)
            ecs_asset.image = image
            ecs_asset.secrets_count = secrets_count

            # Image age in days (ECR only, tag required)
            image_age_days = None
            if image:
                cached_push = ecs_raw.get("image_push_dates", {}).get(image)
                if cached_push is None:
                    registry_id, repository, tag = _parse_ecr_image(image)
                    if registry_id and repository and tag and ecr_client is not None:
                        try:
                            resp = ecr_client.describe_images(
                                registryId=registry_id,
                                repositoryName=repository,
                                imageIds=[{"imageTag": tag}],
                            )
                            details = (resp.get("imageDetails") or [])
                            push_date = details[0].get("imagePushedAt") if details else None
                            ecs_raw["image_push_dates"][image] = push_date
                            cached_push = push_date
                        except botocore.exceptions.ClientError:
                            ecs_raw["image_push_dates"][image] = None
                if isinstance(cached_push, datetime):
                    now = datetime.now(timezone.utc)
                    if cached_push.tzinfo is None:
                        cached_push = cached_push.replace(tzinfo=timezone.utc)
                    image_age_days = (now - cached_push).days
            ecs_asset.image_age_days = image_age_days

            # AdminActions from taskRole
            role_arn = td.get("taskRoleArn") or "none"
            ecs_asset.admin_actions = role_admin_actions.get(role_arn, []) or []

            # Container Insights from cluster settings
            cluster_desc = (ecs_raw.get("clusters_desc", {}) or {}).get(cluster_arn, {}) or {}
            insights_value = ""
            for setting in (cluster_desc.get("settings") or []):
                if (setting.get("name") or "") == "containerInsights":
                    insights_value = setting.get("value") or ""
                    break
            ecs_asset.container_insights = insights_value or "disabled"

            # Direct public exposure (public IP + SG open to world)
            assign_public_ip = (awsvpc.get("assignPublicIp", "DISABLED") == "ENABLED")
            ecs_asset.public_ip_assigned = bool(assign_public_ip)
            task_public_ingress = False
            if ecs_asset.public_ip_assigned:
                for sg_id in (awsvpc.get("securityGroups") or []):
                    if _sg_has_public_ingress(sg_id, sg_raw):
                        task_public_ingress = True
                        break
            ecs_asset.task_public_ingress = task_public_ingress

            # Risk score for exposure context (0..n)
            risk_score = 0
            if ecs_asset.container_privilege in ("root", "privileged", "privileged+root"):
                risk_score += 1
            if ecs_asset.admin_actions:
                risk_score += 1
            if isinstance(ecs_asset.image_age_days, int) and ecs_asset.image_age_days > 90:
                risk_score += 1
            if ecs_asset.exposed_ports:
                for p in ecs_asset.exposed_ports:
                    if p not in (80, 443):
                        risk_score += 1
                        break
            if ecs_asset.execute_command_enabled:
                risk_score += 1
            ecs_asset.risk_score = risk_score

            # Keep attributes for rules.yaml compatibility
            ecs_asset.ContainerPrivilege = ecs_asset.container_privilege
            ecs_asset.ExposureDNS = ecs_asset.exposure_dns
            ecs_asset.ExposureHealthyTargets = str(ecs_asset.exposure_healthy_targets).lower()
            ecs_asset.ExposurePublicIngress = str(ecs_asset.exposure_public_ingress).lower()
            ecs_asset.ExposureType = ecs_asset.exposure_type
            ecs_asset.PublicIpAssigned = str(ecs_asset.public_ip_assigned).lower()
            ecs_asset.TaskPublicIngress = str(ecs_asset.task_public_ingress).lower()
            ecs_asset.AdminActions = ecs_asset.admin_actions
            ecs_asset.NetworkMode = ecs_asset.network_mode
            ecs_asset.ExecuteCommandEnabled = str(ecs_asset.execute_command_enabled).lower()
            ecs_asset.ExposedPorts = ecs_asset.exposed_ports
            ecs_asset.Image = ecs_asset.image
            ecs_asset.ImageAgeDays = ecs_asset.image_age_days
            ecs_asset.SecretsCount = ecs_asset.secrets_count
            ecs_asset.ContainerInsights = ecs_asset.container_insights
            ecs_asset.RiskScore = ecs_asset.risk_score

            # Public flag only for filtering (public_only)
            ecs_asset.public = bool(exposure_dns or ecs_asset.public_ip_assigned)

            cache.save_asset(cache_key, ecs_asset)

        if ecs_asset is None:
            continue
        ecs_asset._ensure_backcompat()

        if public_only and not ecs_asset.public:
            continue
        if search_filter_in(ecs_asset, name_filter):
            assets.append(ecs_asset)

    return assets, authorizations
