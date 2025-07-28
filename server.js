const express = require('express');
const mediasoup = require('mediasoup');
const socketIO = require('socket.io');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Add this route (missing in original)
app.get('/routerRtpCapabilities', (req, res) => {
  res.json(router.rtpCapabilities);
});

const server = app.listen(PORT, '0.0.0.0', () => { // Explicit 0.0.0.0 binding
  console.log(`Server running on port ${PORT}`);
});

const io = socketIO(server, {
  cors: {
    origin: "*", // Allow all origins in production
    methods: ["GET", "POST"]
  }
});

// Mediasoup setup
let worker;
let router;

(async () => {
  worker = await mediasoup.createWorker({
    rtcMinPort: 40000, // Required for Render
    rtcMaxPort: 49999
  });
  
  router = await worker.createRouter({
    mediaCodecs: [
      { kind: 'audio', mimeType: 'audio/opus' },
      { kind: 'video', mimeType: 'video/VP8' }
    ]
  });
})();

// Socket.io logic remains the same as before
io.on('connection', (socket) => {
  console.log('New peer connected:', socket.id);

  socket.on('createTransport', async ({ sender }, callback) => {
    const transport = await router.createWebRtcTransport({
      listenIps: [
        { 
          ip: '0.0.0.0', 
          announcedIp: process.env.RENDER_EXTERNAL_IP || null // Critical for Render
        }
      ],
      enableUdp: true,
      enableTcp: true
    });

    callback({
      id: transport.id,
      iceParameters: transport.iceParameters,
      iceCandidates: transport.iceCandidates,
      dtlsParameters: transport.dlsParameters
    });
  });

  // ... rest of your socket handlers
});
