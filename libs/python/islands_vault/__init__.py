from islands_vault.client import VaultClient, InProcessTransport, HttpTransport


def get_access_token(org, provider, account, *, base_url=None, service=None,
                     principal="stub", island="unknown") -> str:
    if service is not None:
        t = InProcessTransport(service, principal)
    elif base_url is not None:
        t = HttpTransport(base_url, principal)
    else:
        raise ValueError("supply either base_url (HTTP) or service (in-process)")
    return VaultClient(t).get_access_token(org, provider, account, island)


__all__ = ["get_access_token", "VaultClient", "InProcessTransport", "HttpTransport"]
