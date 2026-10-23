import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import crypto from 'node:crypto'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { backupStore, initializeStore, User, LabRecord, AuditLog } from './jsonStore.js'

const app = express()
const port = Number(process.env.PORT || 4000)
const isProduction = process.env.NODE_ENV === 'production'
const jwtSecret = process.env.JWT_SECRET || (isProduction ? '' : 'local-development-only-secret')
if (isProduction && (!jwtSecret || jwtSecret.length < 32)) {
  throw new Error('JWT_SECRET must be at least 32 characters in production')
}
const allowedOrigins = new Set([process.env.CLIENT_ORIGIN, 'http://localhost:5173', 'http://127.0.0.1:5173'].filter(Boolean))
const moduleAccess = {
  samples: ['Admin', 'Lab Technician', 'Researcher', 'Compliance Officer'],
  donors: ['Admin', 'Compliance Officer'],
  batches: ['Admin', 'Lab Technician', 'Researcher'],
  storage: ['Admin', 'Lab Technician'],
  compliance: ['Admin', 'Compliance Officer'],
  projects: ['Admin', 'Researcher'],
}
const attempts = new Map()
const resetTokens = new Map()
const builtInUser = {
  id: 'USR-BUILTIN',
  name: 'Tharun Visu',
  email: 'tharun@stemcell.local',
  department: 'Research Lab',
  password: 'demo1234',
  role: 'Admin',
  approved: true,
}

app.use(helmet())
app.use(cors({ origin: (origin, callback) => (!origin || allowedOrigins.has(origin)) ? callback(null, true) : callback(new Error('Origin not allowed')), credentials: true }))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())

const publicUser = user => ({ id: user.id, name: user.name, email: user.email, department: user.department || '', phone: user.phone || '', role: user.role, approved: user.approved !== false })
const auth = async (req, res, next) => {
  const token = req.cookies?.access_token || req.headers.authorization?.replace('Bearer ', '')
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  try {
    const payload = jwt.verify(token, jwtSecret)
    const user = await User.findOne({ id: payload.id })
    if (!user || user.sessionVersion !== payload.sessionVersion) throw new Error('stale session')
    req.user = user
    next()
  } catch {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Session expired' } })
  }
}
const allow = (...roles) => (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Your role cannot perform this action' } })
const rateLimit = (windowMs, max) => (req, res, next) => {
  const key = `${req.ip}:${req.path}`
  const now = Date.now()
  const entry = attempts.get(key)
  if (!entry || now - entry.started > windowMs) attempts.set(key, { started: now, count: 1 })
  else if (++entry.count > max) return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many attempts. Try again later.' } })
  next()
}
const log = (user, action, entityType, entityId, updatedValues) => AuditLog.create({ user: user.id, action, entityType, entityId, updatedValues })
const list = resource => async (req, res, next) => {
  try {
    const query = String(req.query.q || '').toLowerCase()
    const docs = await LabRecord.find({ resource }).lean()
    const items = docs.map(doc => doc.data).filter(item => !query || JSON.stringify(item).toLowerCase().includes(query))
    res.json({ data: items, total: items.length })
  } catch (error) { next(error) }
}
const create = resource => async (req, res, next) => {
  try {
    const id = req.body.id || `${resource.slice(0, 3).toUpperCase()}-${Date.now()}`
    const data = { ...req.body, id, updated: 'just now' }
    await LabRecord.create({ resource, id, data })
    await log(req.user, 'CREATE', resource, id, data)
    res.status(201).json({ data })
  } catch (error) { next(error) }
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'stemcell-lab-api', database: 'json-file' }))
app.get('/api/backup', auth, allow('Admin'), (_req, res) => {
  res.setHeader('Content-Disposition', `attachment; filename="stemcell-lab-backup-${new Date().toISOString().slice(0, 10)}.json"`)
  res.json(backupStore())
})
app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 8), async (req, res, next) => {
  try {
    const user = await User.findOne({ email: String(req.body.email || '').toLowerCase() })
    if (!user || !await bcrypt.compare(String(req.body.password || ''), user.passwordHash)) return res.status(401).json({ error: { code: 'INVALID_LOGIN', message: 'Email or password is incorrect' } })
    if (!user.approved) return res.status(403).json({ error: { code: 'PENDING_APPROVAL', message: 'Your account is waiting for administrator approval.' } })
    const token = jwt.sign({ id: user.id, sessionVersion: user.sessionVersion }, jwtSecret, { expiresIn: '8h' })
    res.cookie('access_token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 })
    res.json({ data: publicUser(user) })
  } catch (error) { next(error) }
})
app.post('/api/auth/signup', rateLimit(15 * 60 * 1000, 5), async (req, res, next) => {
  try {
    const { name, email, password, department } = req.body
    if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || !password || password.length < 8) return res.status(422).json({ error: { code: 'INVALID_INPUT', message: 'Use a valid email and password with at least 8 characters.' } })
    const normalizedEmail = email.toLowerCase()
    if (await User.exists({ email: normalizedEmail })) return res.status(409).json({ error: { code: 'DUPLICATE_EMAIL', message: 'An account with this email already exists.' } })
    await User.create({ id: `USR-${Date.now()}`, name: name.trim(), email: normalizedEmail, department: department || '', passwordHash: await bcrypt.hash(password, 10), role: 'Researcher', approved: false })
    res.status(201).json({ data: { message: 'Account created. An administrator must approve it before you can sign in.' } })
  } catch (error) { next(error) }
})
app.get('/api/auth/me', auth, (req, res) => res.json({ data: publicUser(req.user) }))
app.post('/api/auth/logout', (_req, res) => { res.clearCookie('access_token'); res.json({ data: { message: 'Signed out.' } }) })
app.patch('/api/auth/profile', auth, async (req, res, next) => { try { req.user.name = String(req.body.name || req.user.name).trim(); req.user.phone = String(req.body.phone || ''); req.user.department = String(req.body.department || ''); await req.user.save(); res.json({ data: publicUser(req.user) }) } catch (error) { next(error) } })
app.post('/api/auth/change-password', auth, async (req, res, next) => { try { if (!await bcrypt.compare(String(req.body.currentPassword || ''), req.user.passwordHash)) return res.status(422).json({ error: { code: 'INVALID_PASSWORD', message: 'Current password is incorrect.' } }); if (!req.body.newPassword || req.body.newPassword.length < 8 || req.body.newPassword !== req.body.confirmPassword) return res.status(422).json({ error: { code: 'INVALID_INPUT', message: 'Passwords must match and be at least 8 characters.' } }); req.user.passwordHash = await bcrypt.hash(req.body.newPassword, 10); req.user.sessionVersion += 1; await req.user.save(); res.json({ data: { message: 'Password updated. Please sign in again.' } }) } catch (error) { next(error) } })
app.post('/api/auth/forgot-password', async (req, res) => { const user = await User.findOne({ email: String(req.body.email || '').toLowerCase() }); if (user) resetTokens.set(crypto.randomUUID(), { userId: user.id, expires: Date.now() + 15 * 60 * 1000 }); res.json({ data: { message: 'If that email exists, reset instructions have been prepared.' } }) })
app.post('/api/auth/reset-password', (_req, res) => res.status(501).json({ error: { code: 'RESET_NOT_CONFIGURED', message: 'Password reset delivery is not configured in this environment.' } }))
app.get('/api/dashboard', auth, async (_req, res, next) => { try { const activeSamples = await LabRecord.countDocuments({ resource: 'samples' }); const cultureBatches = await LabRecord.countDocuments({ resource: 'batches' }); res.json({ data: { activeSamples, cultureBatches, pendingReviews: await LabRecord.countDocuments({ resource: 'compliance', 'data.status': { $in: ['Pending', 'Under Review', 'Needs Action'] } }), storageLocations: await LabRecord.countDocuments({ resource: 'storage' }) } }) } catch (error) { next(error) } })
for (const resource of Object.keys(moduleAccess)) {
  app.get(`/api/${resource}`, auth, allow(...moduleAccess[resource]), list(resource))
  app.post(`/api/${resource}`, auth, allow('Admin', 'Lab Technician', 'Researcher', 'Compliance Officer'), create(resource))
}
app.patch('/api/samples/:id', auth, allow('Admin', 'Lab Technician'), async (req, res, next) => { try { const record = await LabRecord.findOne({ resource: 'samples', id: req.params.id }); if (!record) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Sample not found' } }); Object.assign(record.data, req.body, { updated: 'just now' }); await record.save(); await log(req.user, 'UPDATE', 'samples', record.id, record.data); res.json({ data: record.data }) } catch (error) { next(error) } })
app.get('/api/audit-logs', auth, allow('Admin', 'Compliance Officer'), async (_req, res, next) => { try { const data = await AuditLog.find().sort({ createdAt: -1 }).lean(); res.json({ data, total: data.length }) } catch (error) { next(error) } })
app.get('/api/reports/summary', auth, async (_req, res, next) => { try { const samples = await LabRecord.find({ resource: 'samples' }).lean(); const samplesByStatus = Object.groupBy(samples.map(item => item.data), item => item.status || 'Registered'); res.json({ data: { samplesByStatus, compliance: { pending: await LabRecord.countDocuments({ resource: 'compliance', 'data.status': 'Pending' }), approved: await LabRecord.countDocuments({ resource: 'compliance', 'data.status': 'Approved' }) }, storageOccupancy: 74 } }) } catch (error) { next(error) } })
app.use((_req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found' } }))
app.use((error, _req, res, _next) => { console.error(error); res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'The server could not complete the request.' } }) })

initializeStore().then(async () => {
  const { password, ...userDetails } = builtInUser
  await User.updateOne({ email: userDetails.email }, { ...userDetails, passwordHash: await bcrypt.hash(password, 10) })
  app.listen(port, () => console.log(`StemCell Lab API listening on http://localhost:${port}`))
}).catch(error => { console.error('JSON datastore initialization failed:', error.message); process.exitCode = 1 })
