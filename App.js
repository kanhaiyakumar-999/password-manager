import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  View, Text, TextInput, ScrollView, Pressable, StyleSheet, StatusBar,
  Alert, Switch, ActivityIndicator, Platform, AppState, SafeAreaView,
  KeyboardAvoidingView
} from "react-native";
import * as SecureStore from "expo-secure-store";
import * as Crypto from "expo-crypto";
import * as Clipboard from "expo-clipboard";

const C = {
  bg: "#0B0B12",
  panel: "#151521",
  panel2: "#1D1D2D",
  border: "#343349",
  purple: "#A78BFA",
  text: "#F5F3FF",
  muted: "#9896AF",
  red: "#FF6B81",
  green: "#65E6B4",
};

const VAULT_KEY = "vaultx_entries_v1";
const HASH_KEY = "vaultx_master_hash_v1";
const SALT_KEY = "vaultx_master_salt_v1";
const CHUNK_KEY = "vaultx_chunk_";
const CHUNK_SIZE = 1500;          // SecureStore values are limited to ~2048 bytes
const CLIPBOARD_CLEAR_MS = 30000; // wipe copied passwords after 30 seconds
const EMPTY_FORM = { title: "", username: "", password: "", website: "", notes: "" };

/* ------------------------- storage layer -------------------------
   FIX: expo-secure-store does not exist on web, so Snack's web preview
   broke. On web we fall back to localStorage (NOT secure, demo only).
   ------------------------------------------------------------------ */
const store = Platform.OS === "web"
  ? {
      get: async k => window.localStorage.getItem(k),
      set: async (k, v) => window.localStorage.setItem(k, v),
      del: async k => window.localStorage.removeItem(k),
    }
  : {
      get: k => SecureStore.getItemAsync(k),
      set: (k, v) => SecureStore.setItemAsync(k, v, {
        keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY
      }),
      del: k => SecureStore.deleteItemAsync(k),
    };

/* FIX: the whole vault used to be ONE SecureStore value, which fails once it
   passes ~2 KB (about 8-10 accounts). Now the vault is split into chunks.
   JSON is escaped to pure ASCII so 1 character = 1 byte and chunks never
   cut a multi-byte character in half. */
async function readVault() {
  const meta = await store.get(VAULT_KEY);
  if (!meta) return [];
  if (meta.startsWith("[")) return JSON.parse(meta); // vault saved by the old version
  const count = parseInt(meta.split(":")[1], 10);
  let json = "";
  for (let i = 0; i < count; i++) {
    const part = await store.get(CHUNK_KEY + i);
    if (part == null) throw new Error("Vault data is incomplete");
    json += part;
  }
  return JSON.parse(json);
}

async function writeVault(list) {
  const json = JSON.stringify(list).replace(
    /[\u007f-\uffff]/g,
    c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")
  );
  const parts = [];
  for (let i = 0; i < json.length; i += CHUNK_SIZE) parts.push(json.slice(i, i + CHUNK_SIZE));

  const oldMeta = await store.get(VAULT_KEY);
  const oldCount = oldMeta && oldMeta.startsWith("chunks:")
    ? parseInt(oldMeta.split(":")[1], 10) : 0;

  for (let i = 0; i < parts.length; i++) await store.set(CHUNK_KEY + i, parts[i]);
  await store.set(VAULT_KEY, "chunks:" + parts.length); // commit only after chunks are written
  for (let i = parts.length; i < oldCount; i++) await store.del(CHUNK_KEY + i);
}

/* ------------------------- small helpers ------------------------- */

// FIX: Alert.alert does nothing on web, so use the browser dialogs there.
function notify(title, message) {
  if (Platform.OS === "web") window.alert(`${title}\n${message}`);
  else Alert.alert(title, message);
}

// FIX: modulo on random bytes favoured some characters. This is unbiased.
function randomInt(max) {
  const limit = 256 - (256 % max);
  for (;;) {
    const b = Crypto.getRandomBytes(1)[0];
    if (b < limit) return b % max;
  }
}

/* FIX: the old generator could return a password with none of the selected
   character types (e.g. symbols ticked but no symbol in the result). Now at
   least one character of every selected type is guaranteed, then shuffled. */
function makePassword(length, options) {
  const sets = [];
  if (options.upper) sets.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if (options.lower) sets.push("abcdefghijkmnopqrstuvwxyz");
  if (options.numbers) sets.push("23456789");
  if (options.symbols) sets.push("!@#$%&*-_+=");
  if (!sets.length) sets.push("abcdefghijkmnopqrstuvwxyz", "23456789");

  const all = sets.join("");
  const out = sets.map(s => s[randomInt(s.length)]);
  while (out.length < length) out.push(all[randomInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}

async function hashMaster(password, salt) {
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, salt + password);
}

/* ------------------------- UI parts ------------------------- */

function Button({ title, onPress, secondary, danger, small }) {
  return (
    <Pressable
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        secondary && styles.secondaryButton,
        danger && styles.dangerButton,
        small && styles.smallButton,
        pressed && { opacity: 0.72, transform: [{ scale: 0.97 }] }
      ]}
    >
      <Text style={[
        styles.buttonText,
        secondary && { color: C.purple },
        danger && { color: C.red },
        small && { fontSize: 12 }
      ]}>{title}</Text>
    </Pressable>
  );
}

function Field({ label, value, onChangeText, placeholder, secureTextEntry,
  keyboardType, multiline, onSubmitEditing }) {
  return (
    <View style={styles.fieldWrap}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <TextInput
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder || label}
        placeholderTextColor="#77758D"
        secureTextEntry={secureTextEntry}
        keyboardType={keyboardType || "default"}
        multiline={multiline}
        onSubmitEditing={onSubmitEditing}
        autoCapitalize="none"
        autoCorrect={false}
        style={[styles.input, multiline && { minHeight: 76 }]}
      />
    </View>
  );
}

/* ------------------------- app ------------------------- */

export default function App() {
  const [loading, setLoading] = useState(true);
  const [storageError, setStorageError] = useState(false);
  const [hasMaster, setHasMaster] = useState(false);
  const [unlocked, setUnlocked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [master, setMaster] = useState("");
  const [confirmMaster, setConfirmMaster] = useState("");
  const [entries, setEntries] = useState([]);
  const [screen, setScreen] = useState("vault");
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState(null);
  const [revealed, setRevealed] = useState({});
  const [showFormPw, setShowFormPw] = useState(false);
  const [length, setLength] = useState(18);
  const [opts, setOpts] = useState({ upper: true, lower: true, numbers: true, symbols: true });
  const [generated, setGenerated] = useState("");
  const [form, setForm] = useState(EMPTY_FORM);
  const [toast, setToast] = useState("");

  const fails = useRef(0);
  const lockUntil = useRef(0);
  const toastTimer = useRef(null);
  const clipTimer = useRef(null);

  /* FIX: if secure storage failed to open, the old code showed "Create your
     vault", and creating it OVERWROTE the existing vault with []. Now a
     read error shows a retry screen instead. */
  const init = useCallback(async () => {
    setLoading(true);
    setStorageError(false);
    try {
      const hash = await store.get(HASH_KEY);
      setHasMaster(!!hash);
    } catch {
      setStorageError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { init(); }, [init]);

  // FIX: lock the vault automatically when the app goes to the background.
  useEffect(() => {
    const sub = AppState.addEventListener("change", state => {
      if (state === "background") lockApp();
    });
    return () => sub.remove();
  }, []);

  function showToast(message) {
    setToast(message);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(""), 1800);
  }

  async function setupMaster() {
    if (master.length < 10) {
      notify("Master password", "Use at least 10 characters.");
      return;
    }
    if (master !== confirmMaster) {
      notify("Passwords don't match", "Enter the same password twice.");
      return;
    }

    setBusy(true);
    try {
      // FIX: never overwrite a vault that already exists.
      if (await store.get(HASH_KEY)) {
        setHasMaster(true);
        notify("Vault exists", "A vault already exists. Enter your master password.");
        return;
      }
      const salt = Array.from(Crypto.getRandomBytes(16),
        b => b.toString(16).padStart(2, "0")).join("");
      const hash = await hashMaster(master, salt);
      await store.set(SALT_KEY, salt);
      await writeVault([]);
      await store.set(HASH_KEY, hash); // written last: its existence means setup finished
      setEntries([]);
      setHasMaster(true);
      setUnlocked(true);
      setMaster("");
      setConfirmMaster("");
    } catch {
      notify("Error", "Could not initialize secure storage.");
    } finally {
      setBusy(false);
    }
  }

  // FIX: added a limit on wrong guesses (5 tries, then a 30 second wait).
  async function unlockVault() {
    if (busy) return;
    const wait = lockUntil.current - Date.now();
    if (wait > 0) {
      notify("Too many attempts", `Try again in ${Math.ceil(wait / 1000)} seconds.`);
      return;
    }

    setBusy(true);
    try {
      const salt = await store.get(SALT_KEY);
      const savedHash = await store.get(HASH_KEY);
      const hash = await hashMaster(master, salt || "");
      if (!savedHash || hash !== savedHash) {
        fails.current += 1;
        setMaster("");
        if (fails.current >= 5) {
          fails.current = 0;
          lockUntil.current = Date.now() + 30000;
          notify("Too many attempts", "Wait 30 seconds before trying again.");
        } else {
          notify("Access denied",
            `Incorrect master password. ${5 - fails.current} attempts left.`);
        }
        return;
      }

      setEntries(await readVault());
      fails.current = 0;
      setMaster("");
      setUnlocked(true);
    } catch {
      notify("Error", "Could not read the vault.");
    } finally {
      setBusy(false);
    }
  }

  async function persist(next) {
    try {
      await writeVault(next);
      setEntries(next);
      return true;
    } catch {
      notify("Save failed", "Secure storage could not save the vault.");
      return false;
    }
  }

  function openNew() {
    setEditing(null);
    setForm(EMPTY_FORM);
    setShowFormPw(false);
    setScreen("editor");
  }

  function openEdit(item) {
    setEditing(item.id);
    setForm({
      title: item.title, username: item.username,
      password: item.password, website: item.website || "",
      notes: item.notes || ""
    });
    setShowFormPw(false);
    setScreen("editor");
  }

  async function saveEntry() {
    if (!form.title.trim() || !form.password) {
      notify("Missing information", "Title and password are required.");
      return;
    }

    const clean = { ...form, title: form.title.trim() };
    const next = editing
      ? entries.map(e => e.id === editing ? { ...e, ...clean } : e)
      : [...entries, {
          ...clean,
          id: String(Date.now()) + Math.random().toString(36).slice(2, 7),
          created: new Date().toISOString()
        }];

    if (await persist(next)) setScreen("vault");
  }

  function deleteEntry(item) {
    const doDelete = async () => {
      if (await persist(entries.filter(e => e.id !== item.id))) setRevealed({});
    };
    // FIX: Alert with buttons does nothing on web, so the delete never ran.
    if (Platform.OS === "web") {
      if (window.confirm(`Remove ${item.title} from your vault?`)) doDelete();
      return;
    }
    Alert.alert("Delete credential?", `Remove ${item.title} from your vault?`, [
      { text: "Cancel", style: "cancel" },
      { text: "Delete", style: "destructive", onPress: doDelete }
    ]);
  }

  // FIX: a popup on every copy was annoying (and invisible on web) -> toast.
  // FIX: copied passwords are wiped from the clipboard after 30 seconds.
  async function copyText(value, label, isSecret) {
    if (!value) return;
    await Clipboard.setStringAsync(value);
    showToast(`${label} copied` + (isSecret ? " (clears in 30s)" : ""));
    if (isSecret) {
      clearTimeout(clipTimer.current);
      clipTimer.current = setTimeout(() => Clipboard.setStringAsync(""), CLIPBOARD_CLEAR_MS);
    }
  }

  function lockApp() {
    setUnlocked(false);
    setEntries([]);
    setRevealed({});
    setSearch("");
    setScreen("vault");
    setForm(EMPTY_FORM);
    setGenerated("");
  }

  // FIX: don't allow switching off the last character type.
  function toggleOpt(key, value) {
    if (!value && Object.values(opts).filter(Boolean).length === 1) return;
    setOpts(p => ({ ...p, [key]: value }));
  }

  const filtered = entries.filter(e =>
    [e.title, e.username, e.website].join(" ")
      .toLowerCase().includes(search.toLowerCase())
  );

  /* ------------------------- screens ------------------------- */

  if (loading) {
    return (
      <SafeAreaView style={[styles.app, styles.center]}>
        <ActivityIndicator size="large" color={C.purple} />
        <Text style={styles.muted}>Preparing your vault...</Text>
      </SafeAreaView>
    );
  }

  if (storageError) {
    return (
      <SafeAreaView style={[styles.app, styles.center]}>
        <Text style={styles.heading}>Storage unavailable</Text>
        <Text style={[styles.muted, { textAlign: "center", paddingHorizontal: 30 }]}>
          Secure storage could not be opened. Your data was not changed.
        </Text>
        <View style={{ width: 200 }}>
          <Button title="Try again" onPress={init} />
        </View>
      </SafeAreaView>
    );
  }

  if (!unlocked) {
    return (
      <SafeAreaView style={styles.app}>
        <StatusBar barStyle="light-content" backgroundColor={C.bg} />
        <KeyboardAvoidingView style={{ flex: 1 }}
          behavior={Platform.OS === "ios" ? "padding" : undefined}>
          <ScrollView contentContainerStyle={styles.authScreen}
            keyboardShouldPersistTaps="handled">
            <View style={styles.logo}>
              <Text style={styles.logoIcon}>✳</Text>
            </View>
            <Text style={styles.brand}>VAULT<Text style={{ color: C.purple }}>X</Text></Text>
            <Text style={styles.tagline}>YOUR DIGITAL LIFE. PROTECTED.</Text>

            <View style={styles.authCard}>
              <Text style={styles.heading}>
                {hasMaster ? "Welcome back" : "Create your vault"}
              </Text>
              <Text style={styles.muted}>
                {hasMaster
                  ? "Enter your master password to continue."
                  : "Create a master password to get started."}
              </Text>
              <Field label="Master password" value={master}
                onChangeText={setMaster} secureTextEntry
                onSubmitEditing={hasMaster ? unlockVault : undefined} />
              {!hasMaster && (
                <Field label="Confirm master password" value={confirmMaster}
                  onChangeText={setConfirmMaster} secureTextEntry
                  onSubmitEditing={setupMaster} />
              )}
              <Button
                title={busy ? "Working..." : hasMaster ? "Unlock vault  →" : "Create secure vault  →"}
                onPress={hasMaster ? unlockVault : setupMaster} />
              <Text style={styles.securityNote}>
                Never forget your master password. This starter has no recovery
                feature.
              </Text>
            </View>
            <Text style={styles.footer}>PRIVATE BY DESIGN · LOCAL STORAGE</Text>
          </ScrollView>
        </KeyboardAvoidingView>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.app}>
      <StatusBar barStyle="light-content" backgroundColor={C.bg} />
      <View style={styles.header}>
        <View>
          <Text style={styles.brandSmall}>VAULT<Text style={{ color: C.purple }}>X</Text></Text>
          <Text style={styles.muted}>Your personal security vault</Text>
        </View>
        <Pressable onPress={lockApp} style={styles.lockButton}>
          {/* FIX: the old "♙" glyph is a chess pawn, not a lock */}
          <Text style={{ fontSize: 19 }}>🔒</Text>
        </Pressable>
      </View>

      {screen === "vault" && (
        <ScrollView contentContainerStyle={styles.content}
          keyboardShouldPersistTaps="handled">
          <View style={styles.hero}>
            <Text style={styles.eyebrow}>YOUR VAULT</Text>
            <Text style={styles.heroTitle}>Everything secure.</Text>
            <Text style={styles.muted}>
              {entries.length} saved {entries.length === 1 ? "account" : "accounts"}
            </Text>
            <View style={styles.heroBottom}>
              <View>
                <Text style={styles.eyebrow}>SECURE STORAGE</Text>
                <Text style={styles.secureStatus}>●  On this device</Text>
              </View>
              <Text style={styles.heroSymbol}>✳</Text>
            </View>
          </View>

          <View style={styles.rowBetween}>
            <Text style={styles.sectionTitle}>Your passwords</Text>
            <Button title="+ Add new" onPress={openNew} small />
          </View>

          <TextInput value={search} onChangeText={setSearch}
            placeholder="🔍  Search accounts..."
            placeholderTextColor={C.muted}
            style={styles.search} />

          {filtered.length === 0 ? (
            <View style={styles.empty}>
              <Text style={styles.emptyIcon}>◇</Text>
              <Text style={styles.cardTitle}>
                {search ? "No matching accounts" : "Your vault is empty"}
              </Text>
              <Text style={styles.muted}>
                {search ? "Try another search." : "Add your first login to get started."}
              </Text>
              {!search && <Button title="Add first password" onPress={openNew} />}
            </View>
          ) : filtered.map(item => (
            <View key={item.id} style={styles.entry}>
              <View style={styles.entryTop}>
                <View style={styles.siteIcon}>
                  <Text style={styles.siteInitial}>
                    {(item.title || "?").slice(0, 1).toUpperCase()}
                  </Text>
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={styles.cardTitle}>{item.title}</Text>
                  <Text style={styles.muted} numberOfLines={1}>
                    {item.website || item.username || "Saved account"}
                  </Text>
                </View>
                <Pressable onPress={() => openEdit(item)}>
                  <Text style={styles.actionText}>EDIT</Text>
                </Pressable>
              </View>

              <View style={styles.credential}>
                <Text style={styles.credentialLabel}>USERNAME / EMAIL</Text>
                <View style={styles.rowBetween}>
                  <Text style={styles.credentialValue} numberOfLines={1}>
                    {item.username || "Not set"}
                  </Text>
                  <Pressable onPress={() => copyText(item.username, "Username")}>
                    <Text style={styles.actionText}>COPY</Text>
                  </Pressable>
                </View>
              </View>

              <View style={styles.credential}>
                <Text style={styles.credentialLabel}>PASSWORD</Text>
                <View style={styles.rowBetween}>
                  <Text style={styles.credentialValue} numberOfLines={1}>
                    {revealed[item.id] ? item.password : "••••••••••••"}
                  </Text>
                  <View style={styles.inlineActions}>
                    <Pressable onPress={() =>
                      setRevealed(p => ({ ...p, [item.id]: !p[item.id] }))}>
                      <Text style={styles.actionText}>
                        {revealed[item.id] ? "HIDE" : "SHOW"}
                      </Text>
                    </Pressable>
                    <Pressable onPress={() => copyText(item.password, "Password", true)}>
                      <Text style={styles.actionText}>COPY</Text>
                    </Pressable>
                  </View>
                </View>
              </View>

              {item.notes ? <Text style={styles.note}>{item.notes}</Text> : null}
              <View style={styles.entryFooter}>
                <Text style={styles.muted}>Stored locally</Text>
                <Pressable onPress={() => deleteEntry(item)}>
                  <Text style={{ color: C.red, fontSize: 12 }}>Delete</Text>
                </Pressable>
              </View>
            </View>
          ))}
          <View style={{ height: 30 }} />
        </ScrollView>
      )}

      {screen === "editor" && (
        <ScrollView contentContainerStyle={styles.content}
          keyboardShouldPersistTaps="handled">
          <Pressable onPress={() => setScreen("vault")}>
            <Text style={styles.actionText}>← BACK TO VAULT</Text>
          </Pressable>
          <Text style={styles.pageTitle}>
            {editing ? "Edit account" : "New account"}
          </Text>
          <Text style={styles.muted}>Save your login details on this device.</Text>
          <View style={styles.formCard}>
            <Field label="Account title *" value={form.title}
              onChangeText={v => setForm(p => ({ ...p, title: v }))}
              placeholder="e.g. Google" />
            <Field label="Website / app" value={form.website}
              onChangeText={v => setForm(p => ({ ...p, website: v }))}
              placeholder="e.g. https://example.com" />
            <Field label="Username / email" value={form.username}
              onChangeText={v => setForm(p => ({ ...p, username: v }))}
              placeholder="name@example.com" />
            {/* FIX: password box had no way to see what was typed or generated */}
            <Field label="Password *" value={form.password}
              onChangeText={v => setForm(p => ({ ...p, password: v }))}
              placeholder="Enter password" secureTextEntry={!showFormPw} />
            <View style={styles.buttonRow}>
              <View style={{ flex: 1 }}>
                <Button title={showFormPw ? "Hide" : "Show"} secondary small
                  onPress={() => setShowFormPw(v => !v)} />
              </View>
              <View style={{ flex: 2 }}>
                <Button title="Generate strong password" secondary small
                  onPress={() => {
                    const p = makePassword(18, opts);
                    setForm(old => ({ ...old, password: p }));
                    setShowFormPw(true);
                  }} />
              </View>
            </View>
            <View style={{ height: 15 }} />
            <Field label="Notes (optional)" value={form.notes}
              onChangeText={v => setForm(p => ({ ...p, notes: v }))}
              placeholder="Extra information" multiline />
            <Button title={editing ? "Save changes" : "Save to vault"}
              onPress={saveEntry} />
            <Button title="Cancel" secondary onPress={() => setScreen("vault")} />
          </View>
        </ScrollView>
      )}

      {screen === "generator" && (
        <ScrollView contentContainerStyle={styles.content}>
          <Text style={styles.pageTitle}>Password generator</Text>
          <Text style={styles.muted}>Create a random password.</Text>
          <View style={styles.formCard}>
            <Text style={styles.fieldLabel}>LENGTH: {length} CHARACTERS</Text>
            <View style={styles.rowBetween}>
              <Button title="−" secondary small
                onPress={() => setLength(n => Math.max(8, n - 1))} />
              <Text style={styles.heroTitle}>{length}</Text>
              <Button title="+" secondary small
                onPress={() => setLength(n => Math.min(40, n + 1))} />
            </View>
            {[
              ["upper", "Uppercase letters"],
              ["lower", "Lowercase letters"],
              ["numbers", "Numbers"],
              ["symbols", "Symbols"]
            ].map(([key, label]) => (
              <View key={key} style={styles.switchRow}>
                <Text style={styles.bodyText}>{label}</Text>
                <Switch value={opts[key]}
                  onValueChange={v => toggleOpt(key, v)}
                  trackColor={{ false: C.border, true: C.purple }}
                  thumbColor={C.text} />
              </View>
            ))}
            <Button title="Generate password" onPress={() => {
              setGenerated(makePassword(length, opts));
            }} />
            {generated ? (
              <View style={styles.generatedBox}>
                <Text style={styles.generatedText} selectable>{generated}</Text>
                <Button title="Copy password" secondary
                  onPress={() => copyText(generated, "Generated password", true)} />
                <Button title="Use in new account" onPress={() => {
                  // FIX: this used to keep the title/username/website of the
                  // last edited account, creating a mixed-up duplicate.
                  setForm({ ...EMPTY_FORM, password: generated });
                  setEditing(null);
                  setShowFormPw(true);
                  setScreen("editor");
                }} />
              </View>
            ) : null}
          </View>
        </ScrollView>
      )}

      {!!toast && (
        <View style={styles.toastWrap} pointerEvents="none">
          <Text style={styles.toast}>{toast}</Text>
        </View>
      )}

      <View style={styles.bottomNav}>
        <Pressable onPress={() => setScreen("vault")} style={styles.navItem}>
          <Text style={[styles.navIcon, screen === "vault" && styles.navActive]}>▦</Text>
          <Text style={[styles.navLabel, screen === "vault" && styles.navActive]}>Vault</Text>
        </Pressable>
        <Pressable onPress={() => setScreen("generator")} style={styles.navItem}>
          <Text style={[styles.navIcon, screen === "generator" && styles.navActive]}>✳</Text>
          <Text style={[styles.navLabel, screen === "generator" && styles.navActive]}>Generator</Text>
        </Pressable>
        <Pressable onPress={() => notify(
          "VAULTX security",
          "Your vault is stored on this device. Keep your device protected and never share your master password."
        )} style={styles.navItem}>
          <Text style={styles.navIcon}>◈</Text>
          <Text style={styles.navLabel}>Security</Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  // FIX: SafeAreaView only pads on iOS, so Android gets the status bar height too
  app: { flex: 1, backgroundColor: C.bg, paddingTop: Platform.OS === "android" ? StatusBar.currentHeight || 0 : 0 },
  center: { alignItems: "center", justifyContent: "center", gap: 14 },
  authScreen: { flexGrow: 1, alignItems: "center", justifyContent: "center", padding: 22 },
  logo: { width: 64, height: 64, borderRadius: 22, backgroundColor: C.panel2, borderWidth: 1, borderColor: C.purple, alignItems: "center", justifyContent: "center", marginBottom: 16 },
  logoIcon: { fontSize: 38, color: C.purple },
  brand: { fontSize: 35, fontWeight: "900", letterSpacing: 5, color: C.text },
  brandSmall: { fontSize: 23, fontWeight: "900", letterSpacing: 3, color: C.text },
  tagline: { fontSize: 10, letterSpacing: 2, color: C.muted, marginTop: 7, marginBottom: 30 },
  authCard: { width: "100%", maxWidth: 440, backgroundColor: C.panel, borderWidth: 1, borderColor: C.border, borderRadius: 24, padding: 20 },
  heading: { fontSize: 24, fontWeight: "800", color: C.text, marginBottom: 8 },
  muted: { color: C.muted, fontSize: 13, lineHeight: 20 },
  securityNote: { color: C.muted, fontSize: 11, lineHeight: 17, marginTop: 16, textAlign: "center" },
  footer: { fontSize: 9, color: C.muted, letterSpacing: 1.4, marginTop: 25 },
  header: { paddingHorizontal: 20, paddingTop: 18, paddingBottom: 14, flexDirection: "row", justifyContent: "space-between", alignItems: "center", borderBottomWidth: 1, borderBottomColor: C.border },
  lockButton: { width: 42, height: 42, borderRadius: 14, borderWidth: 1, borderColor: C.border, alignItems: "center", justifyContent: "center" },
  content: { padding: 18, paddingBottom: 30 },
  hero: { backgroundColor: C.panel, borderRadius: 23, padding: 20, borderWidth: 1, borderColor: C.border, marginBottom: 27 },
  eyebrow: { fontSize: 10, letterSpacing: 2, color: C.muted, fontWeight: "700" },
  heroTitle: { fontSize: 25, fontWeight: "800", color: C.text, marginVertical: 8 },
  heroBottom: { borderTopWidth: 1, borderTopColor: C.border, marginTop: 20, paddingTop: 15, flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  secureStatus: { color: C.green, fontSize: 12, marginTop: 6 },
  heroSymbol: { fontSize: 34, color: C.purple },
  rowBetween: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", gap: 10 },
  buttonRow: { flexDirection: "row", gap: 10 },
  sectionTitle: { fontSize: 19, fontWeight: "800", color: C.text },
  search: { backgroundColor: C.panel, borderWidth: 1, borderColor: C.border, borderRadius: 14, paddingHorizontal: 15, paddingVertical: 13, color: C.text, marginTop: 15, marginBottom: 14, fontSize: 14 },
  entry: { backgroundColor: C.panel, borderWidth: 1, borderColor: C.border, borderRadius: 19, padding: 15, marginBottom: 13 },
  entryTop: { flexDirection: "row", alignItems: "center", gap: 11, marginBottom: 15 },
  siteIcon: { width: 43, height: 43, borderRadius: 14, backgroundColor: C.panel2, borderWidth: 1, borderColor: C.border, alignItems: "center", justifyContent: "center" },
  siteInitial: { color: C.purple, fontSize: 20, fontWeight: "800" },
  cardTitle: { color: C.text, fontSize: 15, fontWeight: "700", marginBottom: 3 },
  actionText: { color: C.purple, fontSize: 10, fontWeight: "800", letterSpacing: 0.5 },
  credential: { borderTopWidth: 1, borderTopColor: C.border, paddingTop: 12, paddingBottom: 3, marginTop: 7 },
  credentialLabel: { color: C.muted, fontSize: 9, letterSpacing: 1.2, marginBottom: 8 },
  credentialValue: { color: C.text, fontSize: 13, flex: 1, marginRight: 8 },
  inlineActions: { flexDirection: "row", gap: 14 },
  note: { color: C.muted, fontSize: 12, marginTop: 12 },
  entryFooter: { borderTopWidth: 1, borderTopColor: C.border, marginTop: 12, paddingTop: 10, flexDirection: "row", justifyContent: "space-between" },
  empty: { padding: 24, alignItems: "center", gap: 12, borderWidth: 1, borderStyle: "dashed", borderColor: C.border, borderRadius: 20, marginTop: 10 },
  emptyIcon: { fontSize: 38, color: C.purple },
  button: { borderWidth: 1, borderColor: C.purple, borderRadius: 13, paddingVertical: 13, paddingHorizontal: 16, alignItems: "center", justifyContent: "center", marginTop: 12, backgroundColor: "transparent" },
  secondaryButton: { borderColor: C.border, backgroundColor: C.panel2 },
  dangerButton: { borderColor: C.red },
  smallButton: { paddingVertical: 9, paddingHorizontal: 12, marginTop: 0 },
  buttonText: { fontSize: 13, fontWeight: "800", color: C.purple },
  pageTitle: { fontSize: 28, fontWeight: "900", color: C.text, marginTop: 18, marginBottom: 6 },
  formCard: { backgroundColor: C.panel, borderRadius: 20, borderWidth: 1, borderColor: C.border, padding: 17, marginTop: 20 },
  fieldWrap: { marginBottom: 15 },
  fieldLabel: { color: C.muted, fontSize: 11, fontWeight: "700", marginBottom: 8, letterSpacing: 0.4 },
  input: { backgroundColor: C.bg, borderWidth: 1, borderColor: C.border, borderRadius: 12, paddingHorizontal: 13, paddingVertical: 12, color: C.text, fontSize: 14 },
  bodyText: { color: C.text, fontSize: 14 },
  switchRow: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingVertical: 7, borderBottomWidth: 1, borderBottomColor: C.border },
  generatedBox: { marginTop: 18, backgroundColor: C.bg, borderRadius: 15, borderWidth: 1, borderColor: C.border, padding: 13 },
  generatedText: { color: C.green, fontSize: 16, fontWeight: "700", textAlign: "center", padding: 10 },
  toastWrap: { position: "absolute", left: 0, right: 0, bottom: 84, alignItems: "center" },
  toast: { backgroundColor: C.panel2, color: C.text, borderWidth: 1, borderColor: C.purple, borderRadius: 20, paddingVertical: 9, paddingHorizontal: 16, fontSize: 13, overflow: "hidden" },
  bottomNav: { height: 68, backgroundColor: C.panel, borderTopWidth: 1, borderTopColor: C.border, flexDirection: "row", justifyContent: "space-around", alignItems: "center", paddingBottom: 4 },
  navItem: { alignItems: "center", justifyContent: "center", minWidth: 75 },
  navIcon: { fontSize: 21, color: C.muted, marginBottom: 2 },
  navLabel: { fontSize: 10, color: C.muted },
  navActive: { color: C.purple, fontWeight: "800" }
});