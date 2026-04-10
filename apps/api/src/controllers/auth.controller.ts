import { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import prisma from '../utils/prisma'
import { signToken } from '../utils/jwt'

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, email, password } = req.body

    if (!name || !email || !password) {
      res.status(400).json({ message: 'Todos los campos son requeridos' })
      return
    }

    const existing = await prisma.user.findUnique({ where: { email } })
    if (existing) {
      res.status(409).json({ message: 'El correo ya está registrado' })
      return
    }

    const hashed = await bcrypt.hash(password, 10)
    const user = await prisma.user.create({
      data: { name, email, password: hashed },
    })

    const token = signToken({ userId: user.id, role: user.role })

    res.status(201).json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    })
  } catch {
    res.status(500).json({ message: 'Error interno del servidor' })
  }
}

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      res.status(400).json({ message: 'Correo y contraseña requeridos' })
      return
    }

    const user = await prisma.user.findUnique({ where: { email } })
    if (!user) {
      res.status(401).json({ message: 'Credenciales inválidas' })
      return
    }

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) {
      res.status(401).json({ message: 'Credenciales inválidas' })
      return
    }

    const token = signToken({ userId: user.id, role: user.role })

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    })
  } catch {
    res.status(500).json({ message: 'Error interno del servidor' })
  }
}

export const me = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = (req as any).user?.userId
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, name: true, email: true, role: true, createdAt: true },
    })
    res.json(user)
  } catch {
    res.status(500).json({ message: 'Error interno del servidor' })
  }
}