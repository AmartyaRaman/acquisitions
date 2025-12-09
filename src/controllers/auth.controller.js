import logger from '#config/logger.js';
import { createUser } from '#services/auth.service.js';
import { formatValidationError } from '#utils/format.js';
import { signupSchema, signinSchema } from '#validations/auth.validations.js';
import { jwttoken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { eq } from 'drizzle-orm';
import { comparePassword } from '#services/auth.service.js';

export const signup = async (req, res, next) => {
  try {
    const validationResult = signupSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error)
      });
    }

    const { name, email, password, role } = validationResult.data;

    // Auth service
    const user = await createUser({name, email, password, role});

    const token = jwttoken.sign({ id: user.id, email: user.email, role: user.role });

    cookies.set(res, 'token', token);

    logger.info(`User registered successfully: ${email}`);
    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (e) {
    logger.error('Sign-up error', e);

    if (e.message === 'User with this email already exists') {
      return res.status(409).json({
        message: 'User with this email already exists'
      });
    }

    next(e);
  }
};

export const signin = async (req, res, next) => {
  try {
    const validationResult = signinSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error)
      });
    }

    const { email, password } = validationResult.data;

    // Auth service
    const user = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if (!user.length) throw new Error('User not found');

    const isPasswordValid = await comparePassword(password, user[0].password);

    if (!isPasswordValid) throw new Error('Invalid password');

    const token = jwttoken.sign({ id: user[0].id, email: user[0].email, role: user[0].role });

    cookies.set(res, 'token', token);

    logger.info(`User signed in successfully: ${email}`);
    return res.status(200).json({
      message: 'User signed in successfully',
      user: {
        id: user[0].id,
        name: user[0].name,
        email: user[0].email,
        role: user[0].role
      }
    });
  } catch (e) {
    logger.error('Sign-in error', e);
    next(e);
  }
};

export const signout = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');
    logger.info('User signed out successfully');
    return res.status(200).json({
      message: 'User signed out successfully'
    });
  } catch (e) {
    logger.error('Sign-out error', e);
    next(e);
  }
};