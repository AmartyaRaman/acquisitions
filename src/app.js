// Create your express application here.
import express from 'express';

const app = express();

app.get('/', (req, res) => {
  return res.status(200).json({
    message: "Welcome to Acquisitions API!"
  })
});

export default app;

