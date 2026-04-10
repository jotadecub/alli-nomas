import bcrypt from 'bcryptjs'
import prisma from './prisma'

async function seed() {
  const hashed = await bcrypt.hash('12122004', 10)

  const admin = await prisma.user.upsert({
    where: { email: 'admin@allinomas.com' },
    update: {},
    create: {
      name: 'Admin',
      email: 'admin@allinomas.com',
      password: hashed,
      role: 'ADMIN',
    },
  })

  console.log('Admin creado:', admin.email)
  await prisma.$disconnect()
}

seed()