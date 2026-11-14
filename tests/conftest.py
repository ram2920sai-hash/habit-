import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ['NEXO_ALLOWED_HOSTS']='testserver,localhost,127.0.0.1'
os.environ['DATABASE_URL']=os.getenv('NEXO_TEST_DATABASE_URL','')
os.environ.pop('RENDER',None)


@pytest.fixture(autouse=True)
def database(tmp_path,monkeypatch):
    import server
    monkeypatch.setattr(server,'DB',tmp_path/'test.db')
    monkeypatch.setattr(server,'DATABASE_URL',os.getenv('NEXO_TEST_DATABASE_URL',''))
    monkeypatch.delenv('NEXO_PUBLIC_ORIGIN',raising=False)
    monkeypatch.delenv('NEXO_HTTPS',raising=False)
    monkeypatch.delenv('BREVO_API_KEY',raising=False)
    monkeypatch.delenv('DATABASE_PASSWORD',raising=False)
    monkeypatch.delenv('GOOGLE_CLIENT_ID',raising=False)
    monkeypatch.delenv('GOOGLE_CLIENT_SECRET',raising=False)
    if server.DATABASE_URL:
        from urllib.parse import urlsplit
        parsed=urlsplit(server.DATABASE_URL)
        if parsed.hostname not in ('localhost','127.0.0.1') or parsed.path!='/nexo_test':
            pytest.fail('Tests may only clear a local database explicitly named nexo_test')
        with server.connection() as db:
            db.execute('TRUNCATE users,rate_limits,oauth_flows RESTART IDENTITY CASCADE')
    server.init()
