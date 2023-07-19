import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import 'express-async-errors';
import connectDB from './config/db.config';
import router from './routes';
import errorMiddleware from './middlewares/error.middleware';

const port = process.env.PORT || 5001;

config();

connectDB();

const app = express();

app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', router);

app.use(errorMiddleware);

app.listen(port, () => console.log(`Server runs on port ${port}`));
