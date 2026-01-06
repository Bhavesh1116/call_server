const express = require('express');
const mediasoup = require('mediasoup');
const socketIO = require('socket.io');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

const server = app.listen(PORT, '0.0.0.0', () => { // Explicit 0.0.0.0 binding
  console.log(`Server running on port ${PORT}`);
});

const io = socketIO(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGIN || "*", // Restrict in production via ALLOWED_ORIGIN
    methods: ["GET", "POST"]
  }
});

// Mediasoup setup
let worker;
let router;

(async () => {
  try {
    worker = await mediasoup.createWorker({
      rtcMinPort: 40000, // Required for Render
      rtcMaxPort: 49999
    });

    worker.on('died', () => {
      console.error('Mediasoup worker died, exiting in 2 seconds...');
      setTimeout(() => process.exit(1), 2000);
    });

    router = await worker.createRouter({
      mediaCodecs: [
        { kind: 'audio', mimeType: 'audio/opus' },
        { kind: 'video', mimeType: 'video/VP8' }
      ]
    });

    console.log('Mediasoup worker and router created');
  } catch (err) {
    console.error('Failed to create mediasoup worker/router:', err);
    process.exit(1);
  }
})();

// Route to expose router RTP capabilities — guard in case router isn't ready yet
app.get('/routerRtpCapabilities', (req, res) => {
  if (!router) {
    return res.status(503).json({ error: 'Router not ready' });
  }
  res.json(router.rtpCapabilities);
});

// Socket.io logic
io.on('connection', (socket) => {
  console.log('New peer connected:', socket.id);

  socket.on('createTransport', async ({ sender } = {}, callback) => {
    if (!callback || typeof callback !== 'function') {
      console.warn('createTransport called without a callback from', socket.id);
      return;
    }

    if (!router) {
      return callback({ error: 'Router not ready' });
    }

    try {
      const transport = await router.createWebRtcTransport({
        listenIps: [
          {
            ip: '0.0.0.0',
            announcedIp: process.env.RENDER_EXTERNAL_IP || undefined // use undefined when not set
          }
        ],
        enableUdp: true,
        enableTcp: true
      });

      callback({
        id: transport.id,
        iceParameters: transport.iceParameters,
        iceCandidates: transport.iceCandidates,
        dtlsParameters: transport.dtlsParameters
      });
    } catch (err) {
      console.error('createWebRtcTransport error:', err);
      callback({ error: err.message || 'createWebRtcTransport failed' });
    }
  });

  // TODO: Implement other handlers (connectTransport, produce, consume, etc.) and cleanup on disconnect
  socket.on('disconnect', () => {
    console.log('Peer disconnected:', socket.id);
    // TODO: close transports/producers/consumers owned by this socket
  });
});
