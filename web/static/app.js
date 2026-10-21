// Konfigurasjon for kontekst-simulering (dropdown)
const contextPresets = {
  PLANT_DAY_2FA: {
    location: 'PLANT_FLOOR',
    time: 'DAY_SHIFT',
    two_factor_auth: true,
    managed_device: false,
    label: 'Fabrikk - Dagskift (Arbeidstid, Lokalt nettverk, 2FA) [0x0B]'
  },
  PLANT_NIGHT: {
    location: 'PLANT_FLOOR',
    time: 'NIGHT_SHIFT',
    two_factor_auth: false,
    managed_device: false,
    label: 'Fabrikk - Nattskift (Nattskift, Lokalt nettverk) [0x12]'
  },
  HQ_DAY: {
    location: 'HQ_OFFICE',
    time: 'DAY_SHIFT',
    two_factor_auth: false,
    managed_device: false,
    label: 'Hovedkontor - Dagskift (Oslo LAN) [0x03]'
  },
  VPN_DAY_2FA: {
    location: 'REMOTE_VPN',
    time: 'DAY_SHIFT',
    two_factor_auth: true,
    managed_device: true,
    label: 'Hjemmekontor / VPN - Arbeidstid (Kryptert tunnel, 2FA) [0x0D]'
  },
  MAINTENANCE: {
    location: 'PLANT_FLOOR',
    time: 'MAINTENANCE',
    two_factor_auth: false,
    managed_device: false,
    label: 'Vedlikeholdsvindu (Planlagt driftsstans) [0x20]'
  },
  WEEKEND: {
    location: 'UNTRUSTED_EXTERNAL',
    time: 'WEEKEND',
    two_factor_auth: false,
    managed_device: false,
    label: 'Helg / Helligdag (Stengt anlegg) [0x40]'
  },
  UNTRUSTED: {
    location: 'UNTRUSTED_EXTERNAL',
    time: 'NIGHT_SHIFT',
    two_factor_auth: false,
    managed_device: false,
    label: 'Eksternt nettverk - Utenfor arbeidstid (Ukjent IP) [0x00]'
  }
};

let currentProfile = null;
let currentContextByte = 11; // 0x0B standard

document.addEventListener('DOMContentLoaded', async () => {
  await onContextChange();
  await checkCurrentSession();
});

// Sjekk om bruker allerede har sesjon
async function checkCurrentSession() {
  try {
    const res = await fetch('/api/v1/auth/me');
    if (res.ok) {
      const data = await res.json();
      if (data.authenticated && data.profile) {
        setLoggedIn(data.profile);
      }
    }
  } catch (err) {
    console.error('Session error:', err);
  }
}

// 1 Dropdown meny: Kontekst-simulering
async function onContextChange() {
  const select = document.getElementById('context-select');
  const key = select.value;
  const cfg = contextPresets[key];
  if (!cfg) return;

  try {
    const res = await fetch('/api/v1/context/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg)
    });

    if (res.ok) {
      const data = await res.json();
      currentContextByte = data.context_byte;
      // Hvis bruker er innlogget, sjekk tilgang på nytt under den nye konteksten
      if (currentProfile) {
        await checkAccess();
      }
    }
  } catch (err) {
    console.error('Context error:', err);
  }
}

// Innlogging
async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  const resultBox = document.getElementById('result-box');
  const title = document.getElementById('status-title');
  const content = document.getElementById('status-content');

  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
      const errText = await res.text();
      resultBox.style.display = 'block';
      resultBox.className = 'result-box denied';
      title.innerText = 'Innlogging feilet';
      content.innerText = 'Feil brukernavn eller passord: ' + errText;
      return;
    }

    const data = await res.json();
    setLoggedIn(data.profile);
    await checkAccess();
  } catch (err) {
    resultBox.style.display = 'block';
    resultBox.className = 'result-box denied';
    title.innerText = 'Tilkoblingsfeil';
    content.innerText = err.message;
  }
}

function setLoggedIn(profile) {
  currentProfile = profile;
  document.getElementById('username').value = profile.id;
  document.getElementById('password').value = '********';
  document.getElementById('btn-submit').style.display = 'none';
  document.getElementById('btn-logout').style.display = 'inline-block';
}

async function handleLogout() {
  try {
    await fetch('/api/v1/auth/logout', { method: 'POST' });
  } catch (e) {}

  currentProfile = null;
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('btn-submit').style.display = 'inline-block';
  document.getElementById('btn-logout').style.display = 'none';

  const resultBox = document.getElementById('result-box');
  resultBox.style.display = 'block';
  resultBox.className = 'result-box';
  document.getElementById('status-title').innerText = 'Logget ut';
  document.getElementById('status-content').innerText = 'Ingen aktiv bruker.';
}

function quickFill(user, pass) {
  document.getElementById('username').value = user;
  document.getElementById('password').value = pass;
  document.getElementById('login-form').requestSubmit();
}

// Sjekk tilgang for innlogget bruker mot valgt kontekst
async function checkAccess() {
  const resultBox = document.getElementById('result-box');
  const title = document.getElementById('status-title');
  const content = document.getElementById('status-content');

  if (!currentProfile) {
    resultBox.style.display = 'block';
    resultBox.className = 'result-box denied';
    title.innerText = 'Ikke innlogget';
    content.innerText = 'Vennligst logg inn først for å evaluere ACL-tilgang.';
    return;
  }

  try {
    // Kall evaluering for profilen mot gjeldende kontekst
    const res = await fetch(`/api/v1/profiles/eval-matrix?id=${currentProfile.id}`);
    if (!res.ok) {
      resultBox.style.display = 'block';
      resultBox.className = 'result-box denied';
      title.innerText = 'Feil';
      content.innerText = 'Kunne ikke evaluere rettigheter.';
      return;
    }

    const data = await res.json();
    const ctx = data.active_context;

    // Finn rettigheter som er tillatt under aktiv kontekst
    let allowedList = [];
    let deniedDueToContext = [];

    data.groups.forEach(g => {
      g.rights_check.forEach(r => {
        if (r.allowed) {
          allowedList.push(`${g.group_name}: ${r.name}`);
        } else if (g.has_rights && !g.context_met) {
          deniedDueToContext.push(`${g.group_name}: ${r.name} (Krevde kontekst 0x${g.context_req.toString(16).toUpperCase()})`);
        }
      });
    });

    const hasAnyAccess = allowedList.length > 0;

    resultBox.style.display = 'block';
    resultBox.className = 'result-box ' + (hasAnyAccess ? 'granted' : 'denied');
    title.innerText = hasAnyAccess 
      ? `Tilgang: Tillatt (true) for ${currentProfile.name}`
      : `Tilgang: Avslått (false) under denne konteksten`;

    let html = `
      <div><strong>Bruker:</strong> ${currentProfile.name} (${currentProfile.role}, Subject ${currentProfile.subject_id})</div>
      <div><strong>Aktiv kontekst:</strong> <code>${ctx.context_hex}</code> (${ctx.location}, ${ctx.time})</div>
      <div style="margin-top: 8px;"><strong>Tildelt 64-bit ACL:</strong> <code>${currentProfile.acl_hex}</code></div>
      <div style="margin-top: 10px;"><strong>Innvilgede rettigheter under denne konteksten:</strong></div>
    `;

    if (allowedList.length > 0) {
      html += `<ul style="margin-left: 20px; margin-top: 4px;">`;
      allowedList.forEach(item => {
        html += `<li>${item}</li>`;
      });
      html += `</ul>`;
    } else {
      html += `<div style="color:#f87171; margin-top: 4px;">Ingen rettigheter innvilget. Kontekstbetingelsene er ikke oppfylt.</div>`;
    }

    if (deniedDueToContext.length > 0) {
      html += `<div style="margin-top: 8px; color:#f87171;"><strong>Blokkert pga. manglende kontekstkrav:</strong></div><ul style="margin-left: 20px;">`;
      deniedDueToContext.forEach(item => {
        html += `<li>${item}</li>`;
      });
      html += `</ul>`;
    }

    content.innerHTML = html;
  } catch (err) {
    resultBox.style.display = 'block';
    resultBox.className = 'result-box denied';
    title.innerText = 'Feil';
    content.innerText = err.message;
  }
}
