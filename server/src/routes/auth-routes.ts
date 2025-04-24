import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const login = async (req: Request, res: Response) : Promise<void> => {
  // TODO: If the user exists and the password is correct, return a JWT token
  const { username, password } = req.body;
  try {
    const user  = await User.findOne({ where: { username } });
    if (!user) {
      res.status(401).json({ message: 'Invalid username or password' });
      return;
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ message: 'Invalid username or password' });
      return;
    }
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET || '', {
      expiresIn: '1h',
    });
    res.json({ token });
  } catch (error: any) {
    res.status(500).json({ message: error.message });
  }
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
