import { Request, Response, NextFunction } from 'express'
import { verifyToken } from '../utils/jwt'

export interface AuthRequest extends Request {
  user?: { userId: string; role: 'CLIENT' | 'ADMIN' }
}

export const authenticate = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const header = req.headers.authorization

  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Token requerido' })
    return
  }

  try {
    const token = header.split(' ')[1]
    const payload = verifyToken(token)
    req.user = payload
    next()
  } catch {
    res.status(401).json({ message: 'Token inválido o expirado' })
  }
}

export const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction): void => {
  if (req.user?.role !== 'ADMIN') {
    res.status(403).json({ message: 'Acceso restringido' })
    return
  }
  next()
}