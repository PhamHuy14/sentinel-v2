const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs   = require('fs/promises');
const { runUrlScan, runProjectScan, getChecklist } = require('../engine/scanner/scan-engine');
const { buildJsonReport, buildHtmlReport, getSuggestedFilename } = require('../engine/report/report-engine');

function createWindow() {
  const win = new BrowserWindow({
    width: 1380, height: 920, minWidth: 1100, minHeight: 760,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
  });
  if (process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  }
}

// ── Shared abort controller for stop-scan ─────────────────────────────────
let currentScanAbort = null;

ipcMain.handle('scan:url', async (event, payload) => {
  // Cancel any previous scan
  currentScanAbort?.abort('New scan started');

  const ac = new AbortController();
  currentScanAbort = ac;

  try {
    const onProgress = (msg) => {
      try { event.sender.send('scan:progress', msg); } catch (_) {}
    };
    return await runUrlScan(payload?.url || '', {
      auth:        payload?.auth      || {},
      maxDepth:    payload?.maxDepth  ?? 1,
      maxBudget:   payload?.maxBudget ?? 30,
      onProgress,
      abortSignal: ac.signal,
    });
  } catch (error) {
    if (ac.signal.aborted) {
      return { ok: false, error: 'Scan đã bị hủy.', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
    }
    return { ok: false, error: error?.message || 'URL scan failed', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
  } finally {
    if (currentScanAbort === ac) currentScanAbort = null;
  }
});

ipcMain.handle('scan:project', async (event, payload) => {
  currentScanAbort?.abort('New scan started');
  const ac = new AbortController();
  currentScanAbort = ac;

  try {
    const onProgress = (msg) => {
      try { event.sender.send('scan:progress', msg); } catch {}
    };
    return await runProjectScan(payload?.folderPath || '', { onProgress, abortSignal: ac.signal });
  } catch (error) {
    if (ac.signal.aborted) {
      return { ok: false, error: 'Scan đã bị hủy.', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
    }
    return { ok: false, error: error?.message || 'Project scan failed', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
  } finally {
    if (currentScanAbort === ac) currentScanAbort = null;
  }
});

// ── Stop Scan ─────────────────────────────────────────────────────────────
ipcMain.handle('scan:stop', () => {
  if (currentScanAbort) {
    currentScanAbort.abort('User cancelled');
    return { ok: true };
  }
  return { ok: false, error: 'No active scan' };
});

ipcMain.handle('checklist:get', async () => {
  try { return { ok: true, data: getChecklist() }; }
  catch (error) { return { ok: false, error: error?.message || 'Checklist load failed' }; }
});

ipcMain.handle('dialog:pickFolder', async () => {
  const result = await dialog.showOpenDialog({ properties: ['openDirectory'] });
  if (result.canceled || !result.filePaths?.length) return { ok: false };
  return { ok: true, folderPath: result.filePaths[0] };
});

ipcMain.handle('docs:open', async (_event, url) => {
  try { await shell.openExternal(url); return { ok: true }; }
  catch (error) { return { ok: false, error: error?.message }; }
});

ipcMain.handle('report:export', async (_event, payload) => {
  try {
    const format     = payload?.format === 'json' ? 'json' : 'html';
    const scanResult = payload?.scanResult;
    if (!scanResult) throw new Error('Không có dữ liệu scan để export.');

    const content    = format === 'json' ? buildJsonReport(scanResult) : buildHtmlReport(scanResult);
    const saveResult = await dialog.showSaveDialog({
      title: 'Export report',
      defaultPath: getSuggestedFilename(scanResult, format),
      filters: format === 'json'
        ? [{ name: 'JSON', extensions: ['json'] }]
        : [{ name: 'HTML', extensions: ['html'] }],
    });

    if (saveResult.canceled || !saveResult.filePath) return { ok: false, canceled: true };
    await fs.writeFile(saveResult.filePath, content, 'utf8');
    return { ok: true, filePath: saveResult.filePath };
  } catch (error) {
    return { ok: false, error: error?.message || 'Export failed' };
  }
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
