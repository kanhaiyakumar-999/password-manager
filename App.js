import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, TextInput, Button, FlatList, StyleSheet,
  SafeAreaView, Pressable, Alert, ActivityIndicator, Modal, ScrollView
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';

const INDEX_KEY = 'vault_index';           // list of entry IDs
const ENTRY_PREFIX = 'vault_entry_';       // one key per entry
const MASTER_KEY = 'vault_master_hash';    // hashed master password
const SALT_KEY = 'vault_salt';

export default function App() {
  // ---- Auth state ----
  const [masterHash, setMasterHash] = useState(null);
  const [masterInput, setMasterInput] = useState('');
  const [isFirstRun, setIsFirstRun] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);
  const [unlocked, setUnlocked] = useState(false);

  // ---- Vault state ----
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(false);

  // ---- Form state ----
  const [title, setTitle] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // ---- UI state ----
  const [revealId, setRevealId] = useState(null);
  const [editingId, setEditingId] = useState(null);

  // ==================================================
  // 1. Check if a master password has been set
  // ==================================================
  useEffect(() => {
    (async () => {
      try {
        const existing = await SecureStore.getItemAsync(MASTER_KEY);
        if (existing) {
          setMasterHash(existing);
          setIsFirstRun(false);
        } else {
          setIsFirstRun(true);
        }
      } catch (e) {
        console.warn('master check failed', e);
        setIsFirstRun(true);
      } finally {
        setAuthChecked(true);
      }
    })();
  }, []);

  // ==================================================
  // 2. Hash a master password (SHA-256 + salt)
  // ==================================================
  async function hashMaster(pw) {
    let salt = await SecureStore.getItemAsync(SALT_KEY);
    if (!salt) {
      const saltBytes = await Crypto.getRandomBytesAsync(16);
      salt = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      await SecureStore.setItemAsync(SALT_KEY, salt);
    }
    const digest = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      salt + '::' + pw
    );
    return digest;
  }

  // ==================================================
  // 3. Setup / Unlock
  // ==================================================
  async function handleSetup() {
    if (masterInput.length < 4) {
      Alert.alert('Too short', 'Master password must be at least 4 characters.');
      return;
    }
    const h = await hashMaster(masterInput);
    await SecureStore.setItemAsync(MASTER_KEY, h);
    setMasterHash(h);
    setMasterInput('');
    setIsFirstRun(false);
    setUnlocked(true);
    await loadVault();
  }

  async function handleUnlock() {
    const h = await hashMaster(masterInput);
    if (h === masterHash) {
      setUnlocked(true);
      setMasterInput('');
      await loadVault();
    } else {
      Alert.alert('Wrong password', 'That master password is incorrect.');
      setMasterInput('');
    }
  }

  // ==================================================
  // 4. Load vault (per-entry keys, no 2KB limit)
  // ==================================================
  const loadVault = useCallback(async () => {
    setLoading(true);
    try {
      const idxRaw = await SecureStore.getItemAsync(INDEX_KEY);
      const ids = idxRaw ? JSON.parse(idxRaw) : [];
      const loaded = [];
      for (const id of ids) {
        const raw = await SecureStore.getItemAsync(ENTRY_PREFIX + id);
        if (raw) loaded.push(JSON.parse(raw));
      }
      setEntries(loaded);
    } catch (e) {
      console.warn('loadVault failed', e);
      Alert.alert('Error', 'Failed to load vault.');
    } finally {
      setLoading(false);
    }
  }, []);

  // ==================================================
  // 5. Save / Update / Delete entries
  // ==================================================
  async function persistIndex(ids) {
    await SecureStore.setItemAsync(INDEX_KEY, JSON.stringify(ids));
  }

  async function saveEntry() {
    if (!title.trim() || !password.trim()) {
      Alert.alert('Error', 'Title and Password are required.');
      return;
    }

    try {
      if (editingId) {
        const updated = { id: editingId, title: title.trim(), username: username.trim(), password };
        await SecureStore.setItemAsync(ENTRY_PREFIX + editingId, JSON.stringify(updated));
        setEntries(prev => prev.map(e => (e.id === editingId ? updated : e)));
        setEditingId(null);
      } else {
        const id = Date.now().toString() + '_' + Math.floor(Math.random() * 1000);
        const entry = { id, title: title.trim(), username: username.trim(), password };
        await SecureStore.setItemAsync(ENTRY_PREFIX + id, JSON.stringify(entry));
        const newIds = [...entries.map(e => e.id), id];
        await persistIndex(newIds);
        setEntries(prev => [...prev, entry]);
      }
      setTitle(''); setUsername(''); setPassword('');
    } catch (e) {
      console.warn('saveEntry failed', e);
      Alert.alert('Error', 'Could not save entry.');
    }
  }

  async function deleteEntry(id) {
    Alert.alert('Delete?', 'This cannot be undone.', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete', style: 'destructive', onPress: async () => {
          try {
            await SecureStore.deleteItemAsync(ENTRY_PREFIX + id);
            const newIds = entries.filter(e => e.id !== id).map(e => e.id);
            await persistIndex(newIds);
            setEntries(prev => prev.filter(e => e.id !== id));
            if (revealId === id) setRevealId(null);
          } catch (e) {
            console.warn('delete failed', e);
          }
        }
      }
    ]);
  }

  function startEdit(entry) {
    setEditingId(entry.id);
    setTitle(entry.title);
    setUsername(entry.username);
    setPassword(entry.password);
  }

  function cancelEdit() {
    setEditingId(null);
    setTitle(''); setUsername(''); setPassword('');
  }

  // ==================================================
  // 6. Password generator (FIXED — uses async API)
  // ==================================================
  async function generatePassword() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}';
    const LEN = 16;
    try {
      const bytes = await Crypto.getRandomBytesAsync(LEN);
      let pass = '';
      for (let i = 0; i < LEN; i++) {
        pass += chars[bytes[i] % chars.length];
      }
      setPassword(pass);
    } catch (e) {
      console.warn('rng failed', e);
      Alert.alert('Error', 'Could not generate a password.');
    }
  }

  // ==================================================
  // 7. Copy to clipboard (awaited)
  // ==================================================
  async function copyToClipboard(text, label = 'Value') {
    try {
      await Clipboard.setStringAsync(text);
      Alert.alert('Copied', `${label} copied to clipboard.`);
    } catch (e) {
      Alert.alert('Error', 'Clipboard failed.');
    }
  }

  // ==================================================
  // 8. Lock app
  // ==================================================
  function lock() {
    setUnlocked(false);
    setEntries([]);
    cancelEdit();
    setRevealId(null);
  }

  // ==================================================
  // RENDER — Loading
  // ==================================================
  if (!authChecked) {
    return (
      <SafeAreaView style={styles.center}>
        <ActivityIndicator size="large" color="#007AFF" />
        <Text style={{ marginTop: 12, color: '#555' }}>Checking vault…</Text>
      </SafeAreaView>
    );
  }

  // ==================================================
  // RENDER — Auth screen
  // ==================================================
  if (!unlocked) {
    return (
      <SafeAreaView style={styles.center}>
        <Text style={styles.logo}>🔐 VaultX</Text>
        <Text style={styles.sub}>
          {isFirstRun ? 'Create a master password' : 'Enter your master password'}
        </Text>
        <TextInput
          style={[styles.input, { width: '85%', textAlign: 'center' }]}
          placeholder="Master password"
          value={masterInput}
          onChangeText={setMasterInput}
          secureTextEntry
          autoCapitalize="none"
        />
        <View style={{ height: 12 }} />
        <Button
          title={isFirstRun ? 'Create Vault' : 'Unlock'}
          onPress={isFirstRun ? handleSetup : handleUnlock}
        />
        {isFirstRun && (
          <Text style={styles.hint}>
            ⚠️ If you forget this password, your vault cannot be recovered.
          </Text>
        )}
      </SafeAreaView>
    );
  }

  // ==================================================
  // RENDER — Main app
  // ==================================================
  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.topBar}>
        <Text style={styles.header}>VaultX</Text>
        <Pressable onPress={lock}>
          <Text style={styles.lockText}>Lock</Text>
        </Pressable>
      </View>

      <ScrollView keyboardShouldPersistTaps="handled">
        <View style={styles.form}>
          <Text style={styles.formTitle}>
            {editingId ? 'Edit Entry' : 'New Entry'}
          </Text>
          <TextInput
            style={styles.input}
            placeholder="Account Title (e.g. Google)"
            value={title}
            onChangeText={setTitle}
          />
          <TextInput
            style={styles.input}
            placeholder="Username / Email"
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
          />
          <View style={styles.passwordRow}>
            <TextInput
              style={[styles.input, { flex: 1, marginBottom: 0 }]}
              placeholder="Password"
              value={password}
              onChangeText={setPassword}
              secureTextEntry={false}
              autoCapitalize="none"
            />
            <Button title="Generate" onPress={generatePassword} />
          </View>
          <View style={{ height: 10 }} />
          <Button
            title={editingId ? 'Update Entry' : 'Save to Vault'}
            onPress={saveEntry}
          />
          {editingId && (
            <>
              <View style={{ height: 8 }} />
              <Button title="Cancel Edit" color="#888" onPress={cancelEdit} />
            </>
          )}
        </View>

        {loading ? (
          <ActivityIndicator style={{ marginTop: 20 }} />
        ) : entries.length === 0 ? (
          <Text style={styles.empty}>No entries yet. Add one above.</Text>
        ) : (
          <FlatList
            data={entries}
            keyExtractor={item => item.id}
            scrollEnabled={false}
            renderItem={({ item }) => (
              <View style={styles.card}>
                <Text style={styles.cardTitle}>{item.title}</Text>
                {!!item.username && (
                  <Text style={styles.cardText}>User: {item.username}</Text>
                )}
                <Text style={styles.cardText}>
                  Password: {revealId === item.id ? item.password : '••••••••'}
                </Text>

                <View style={styles.actionRow}>
                  <Pressable onPress={() => setRevealId(revealId === item.id ? null : item.id)}>
                    <Text style={styles.actionText}>
                      {revealId === item.id ? 'Hide' : 'Show'}
                    </Text>
                  </Pressable>
                  <Pressable onPress={() => copyToClipboard(item.username, 'Username')}>
                    <Text style={styles.actionText}>Copy User</Text>
                  </Pressable>
                  <Pressable onPress={() => copyToClipboard(item.password, 'Password')}>
                    <Text style={styles.actionText}>Copy Pass</Text>
                  </Pressable>
                  <Pressable onPress={() => startEdit(item)}>
                    <Text style={styles.editText}>Edit</Text>
                  </Pressable>
                  <Pressable onPress={() => deleteEntry(item.id)}>
                    <Text style={styles.deleteText}>Delete</Text>
                  </Pressable>
                </View>
              </View>
            )}
          />
        )}

        <View style={{ height: 40 }} />
      </ScrollView>
    </SafeAreaView>
  );
}

// ==================================================
// STYLES
// ==================================================
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f0f5', padding: 20 },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: '#f0f0f5', padding: 20 },
  logo: { fontSize: 42, marginBottom: 12 },
  sub: { fontSize: 16, color: '#555', marginBottom: 20, textAlign: 'center' },
  hint: { marginTop: 20, fontSize: 12, color: '#888', textAlign: 'center', paddingHorizontal: 30 },
  topBar: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, marginTop: 20 },
  header: { fontSize: 28, fontWeight: 'bold' },
  lockText: { color: '#FF3B30', fontWeight: 'bold', fontSize: 16 },
  form: { backgroundColor: '#fff', padding: 15, borderRadius: 10, marginBottom: 20 },
  formTitle: { fontSize: 16, fontWeight: '600', marginBottom: 10, color: '#333' },
  input: { borderWidth: 1, borderColor: '#ccc', padding: 10, borderRadius: 5, marginBottom: 10 },
  passwordRow: { flexDirection: 'row', alignItems: 'center', marginBottom: 10, gap: 10 },
  card: { backgroundColor: '#fff', padding: 15, borderRadius: 10, marginBottom: 10 },
  cardTitle: { fontSize: 18, fontWeight: 'bold' },
  cardText: { color: '#555', marginTop: 5, fontFamily: 'monospace' },
  actionRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 14, marginTop: 15 },
  actionText: { color: '#007AFF', fontWeight: 'bold' },
  editText: { color: '#FF9500', fontWeight: 'bold' },
  deleteText: { color: '#FF3B30', fontWeight: 'bold' },
  empty: { textAlign: 'center', color: '#888', marginTop: 30, fontStyle: 'italic' }
});
