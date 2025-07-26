const express = require('express');
const mediasoup = require('mediasoup');
const socketIO = require('socket.io');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files (HTML, JS)
app.use(express.static(path.join(__dirname, 'public')));

const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

const io = socketIO(server);

// Mediasoup setup
let worker;
let router;
const peers = new Map();

(async () => {
  worker = await mediasoup.createWorker();
  router = await worker.createRouter({
    mediaCodecs: [
      { kind: 'audio', mimeType: 'audio/opus' },
      { kind: 'video', mimeType: 'video/VP8' },
    ],
  });
})();

io.on('connection', (socket) => {
  console.log('New peer connected:', socket.id);
  peers.set(socket.id, { socket });

  socket.on('disconnect', () => {
    console.log('Peer disconnected:', socket.id);
    peers.delete(socket.id);
  });

  // WebRTC transport creation
  socket.on('createTransport', async ({ sender }, callback) => {
    const transport = await router.createWebRtcTransport({
      listenIps: [{ ip: '0.0.0.0', announcedIp: null }],
      enableUdp: true,
      enableTcp: true,
      preferUdp: true,
    });

    peers.get(socket.id).transport = transport;

    callback({
      id: transport.id,
      iceParameters: transport.iceParameters,
      iceCandidates: transport.iceCandidates,
      dtlsParameters: transport.dtlsParameters,
    });
  });

  // Handle WebRTC connection
  socket.on('connectTransport', async ({ dtlsParameters }, callback) => {
    await peers.get(socket.id).transport.connect({ dtlsParameters });
    callback({ success: true });
  });

  // Produce media (audio/video)
  socket.on('produce', async ({ kind, rtpParameters }, callback) => {
    const producer = await peers.get(socket.id).transport.produce({
      kind,
      rtpParameters,
    });

    callback({ id: producer.id });

    // Broadcast to other peers
    socket.broadcast.emit('newProducer', { producerId: producer.id, kind });
  });
});
