// Import the "ingredients"
const express = require('express');
const bodyParser = require('body-parser');
const TelegramBot = require('node-telegram-bot-api');

// --- PUT YOUR SECRETS HERE ---
const BOT_TOKEN = '8336710006:AAE0Z-bKeRQN7QTphSB3WQR3kZLMAApgsFM'; // Paste your token from BotFather
const CHAT_ID = '727210504'; // Paste your ID from @getmyid_bot
// -----------------------------

// Setup the bot and server
const bot = new TelegramBot(BOT_TOKEN);
const app = express();
app.use(bodyParser.json());

// This is the endpoint Helius will send data to
app.post('/webhook', (req, res) => {
  const transactions = req.body;

  try {
    for (const tx of transactions) {
      // This is the filter for new token mints.
      if (tx.description && tx.description.includes("Initialize Mint")) {
        
        // We found one!
        const tokenAddress = tx.instructions[0].accounts[0];
        const signature = tx.signature;
        const message = `🚨 New Token Minted! 🚨\n\nAddress: ${tokenAddress}\n\nSolscan: https://solscan.io/tx/${signature}`;
        
        // Send the notification to your Telegram
        bot.sendMessage(CHAT_ID, message);
      }
    }
  } catch (err) {
    console.error("Error processing transaction:", err.message);
  }

  // Tell Helius "OK"
  res.status(200).send('OK');
});

// A simple test route to make sure your server is alive
app.get('/', (req, res) => {
  res.send('Your token bot is alive!');
});

// Start the server
// Vercel will automatically use the correct port
module.exports = app;

