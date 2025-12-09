import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { eq } from 'drizzle-orm';

export const hashPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error('Error hashing the password', e);
    throw new Error('Error hashing');
  }
};

export const createUser = async ({name, email, password, role = 'user'}) => {
  try {
    const exisitingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if (exisitingUser.length>0) throw new Error('User with this email already exists');

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({name, email, password: password_hash, role})
      .returning({ id: users.id, name: users.name, email: users.email, role: users.role, created_at: users.created_at});
    
    logger.info(`User created successfully: ${email}`);
    return newUser;
    
  } catch (e) {
    logger.error('Error creating user', e);
    throw new Error('Error creating user');
  }
};

export const comparePassword = async (password, password_hash) => {
  try {
    return await bcrypt.compare(password, password_hash);
  } catch (e) {
    logger.error('Error comparing password', e);
    throw new Error('Error comparing password');
  }
};