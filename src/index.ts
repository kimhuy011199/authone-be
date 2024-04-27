import express from 'express';
import cors from 'cors';
import 'express-async-errors';
import connectDB from './config/db.config';
import router from './routes';
import errorMiddleware from './middlewares/error.middleware';
import { PORT } from './config/env.config';

connectDB();

export const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api', router);

// Error handling middleware
app.use(errorMiddleware);

// Start the server
app.listen(PORT, () => console.log(`Server runs on PORT ${PORT}`));
