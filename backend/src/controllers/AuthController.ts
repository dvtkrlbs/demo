import { Request, Response } from "express";
import { User } from "../models/User";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const SECRET_KEY = process.env.JWT_SECRET || "secret_key";

//📌 1️⃣ NEW USER  SIGNUP

export const signup = async (req: Request, res: Response): Promise<void> => {
    try {
        const { name, email, password, termsAccepted } = req.body;

        if (!termsAccepted) {
            res.status(400).json({ error: "You have to accept the terms." });
        }

        if (password.length < 8) {
            res.status(400).json({
                error: "Password have to be at least 8 characters",
            });
        }

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            res.status(401).json({ error: "User exists" });
            return;
        }

        const hash = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            email,
            name,
            password,
            hash,
            termsAccepted,
        });

        res.status(201).json({
            id: newUser.id,
            email,
            name,
            createdAt: new Date(),
        });
    } catch (e) {
        res.status(500).json({ error: "Something went wrong " });
    }
    // Fill in the code
};

// 📌 2️⃣ Login
export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password } = req.body;

        // Search new user
        const user = await User.findOne({ where: { email } });
        if (!user) {
            res.status(401).json({ error: "Invalid credentials" });
            return;
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            res.status(401).json({ error: "Invalid credentials" });
            return;
        }

        // ✅ Create JWT
        const token = jwt.sign({ id: user.id }, "your_secret_key", {
            expiresIn: "1h",
        });

        res.json({ message: "Login successful!", token });
    } catch (error) {
        res.status(500).json({ error: "Error logging in" });
    }
};
