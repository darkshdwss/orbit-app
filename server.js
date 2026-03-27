// ─────────────────────────────────────────────
//  ORBIT — Backend Server
//  Express + MongoDB + bcrypt + JWT + Socket.io
// ─────────────────────────────────────────────
const express    = require('express');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const path       = require('path');
const cors       = require('cors');
const http       = require('http');
const { Server } = require('socket.io');
const { MongoClient, ObjectId } = require('mongodb');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const PORT        = process.env.PORT  || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'orbit-super-secret-change-in-production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/orbit';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'orbit-admin-secret-2026';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname), { index: false }));

let db;
async function connectDB(){
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db('orbit');
  console.log('✅ MongoDB connected');
}
function uid(){ return new ObjectId().toString(); }
function auth(req,res,next){
  const h=req.headers['authorization'];
  if(!h) return res.status(401).json({error:'No token'});
  try{ req.user=jwt.verify(h.split(' ')[1],JWT_SECRET); next(); }
  catch{ res.status(401).json({error:'Invalid token'}); }
}
function adminAuth(req,res,next){
  const k=req.headers['x-admin-key']||req.query.key;
  if(k!==ADMIN_KEY) return res.status(401).json({error:'Unauthorized'});
  next();
}
function verifyToken(t){ try{ return jwt.verify(t,JWT_SECRET); }catch{ return null; } }

// ── AUTH ──────────────────────────────────────
app.post('/api/register', async(req,res)=>{
  const {username,email,password}=req.body;
  if(!username||!email||!password) return res.status(400).json({error:'All fields required'});
  if(password.length<6) return res.status(400).json({error:'Password min 6 chars'});
  const el=email.trim().toLowerCase();
  const ex=await db.collection('users').findOne({$or:[{email:el},{username:username.trim()}]});
  if(ex) return res.status(409).json({error:ex.email===el?'Email taken':'Username taken'});
  try{
    const hash=await bcrypt.hash(password,10);
    const uid2=uid();
    const user={_id:uid2,id:uid2,username:username.trim(),email:el,password:hash,created_at:new Date().toISOString()};
    await db.collection('users').insertOne(user);
    const defs=[
      {_id:uid(),user_id:uid2,name:'Personal',color:'#6ee7f7',created_at:new Date().toISOString()},
      {_id:uid(),user_id:uid2,name:'Work',color:'#c084fc',created_at:new Date().toISOString()},
      {_id:uid(),user_id:uid2,name:'Health',color:'#4ade80',created_at:new Date().toISOString()},
    ];
    await db.collection('projects').insertMany(defs);
    const token=jwt.sign({id:uid2,username:user.username},JWT_SECRET,{expiresIn:'7d'});
    res.json({token,username:user.username});
  }catch(e){console.error(e);res.status(500).json({error:'Server error'});}
});
app.post('/api/login', async(req,res)=>{
  const {email,password}=req.body;
  if(!email||!password) return res.status(400).json({error:'Email and password required'});
  const user=await db.collection('users').findOne({email:email.trim().toLowerCase()});
  if(!user) return res.status(401).json({error:'Invalid email or password'});
  const ok=await bcrypt.compare(password,user.password);
  if(!ok) return res.status(401).json({error:'Invalid email or password'});
  const token=jwt.sign({id:user.id||user._id,username:user.username},JWT_SECRET,{expiresIn:'7d'});
  res.json({token,username:user.username});
});
app.get('/api/me', auth, async(req,res)=>{
  const u=await db.collection('users').findOne({id:req.user.id});
  if(!u) return res.status(404).json({error:'Not found'});
  const {password,...safe}=u; res.json(safe);
});

// ── PROJECTS ──────────────────────────────────
app.get('/api/projects', auth, async(req,res)=>{
  const p=await db.collection('projects').find({user_id:req.user.id}).toArray();
  res.json(p.map(x=>({...x,id:x._id})));
});
app.post('/api/projects', auth, async(req,res)=>{
  const {name,color}=req.body; if(!name) return res.status(400).json({error:'Name required'});
  const id=uid();
  const p={_id:id,id,user_id:req.user.id,name:name.trim(),color:color||'#6ee7f7',created_at:new Date().toISOString()};
  await db.collection('projects').insertOne(p); res.json(p);
});
app.delete('/api/projects/:id', auth, async(req,res)=>{
  const r=await db.collection('projects').deleteOne({_id:req.params.id,user_id:req.user.id});
  if(!r.deletedCount) return res.status(404).json({error:'Not found'});
  res.json({success:true});
});

// ── TASKS ─────────────────────────────────────
app.get('/api/tasks', auth, async(req,res)=>{
  const t=await db.collection('tasks').find({user_id:req.user.id}).sort({created_at:-1}).toArray();
  res.json(t.map(x=>({...x,id:x._id})));
});
app.post('/api/tasks', auth, async(req,res)=>{
  const {name,notes,proj_id,priority,due}=req.body;
  if(!name) return res.status(400).json({error:'Name required'});
  const id=uid();
  const t={_id:id,id,user_id:req.user.id,proj_id:proj_id||null,name:name.trim(),notes:notes||'',priority:priority||'medium',due:due||'',done:false,created_at:new Date().toISOString()};
  await db.collection('tasks').insertOne(t); res.json(t);
});
app.put('/api/tasks/:id', auth, async(req,res)=>{
  const {name,notes,proj_id,priority,due,done}=req.body;
  const u={};
  if(name!==undefined) u.name=name; if(notes!==undefined) u.notes=notes;
  if(proj_id!==undefined) u.proj_id=proj_id; if(priority!==undefined) u.priority=priority;
  if(due!==undefined) u.due=due; if(done!==undefined) u.done=done;
  await db.collection('tasks').updateOne({_id:req.params.id,user_id:req.user.id},{$set:u});
  const t=await db.collection('tasks').findOne({_id:req.params.id});
  res.json({...t,id:t._id});
});
app.delete('/api/tasks/:id', auth, async(req,res)=>{
  const r=await db.collection('tasks').deleteOne({_id:req.params.id,user_id:req.user.id});
  if(!r.deletedCount) return res.status(404).json({error:'Not found'});
  res.json({success:true});
});

// ── FRIENDS ───────────────────────────────────
app.get('/api/friends', auth, async(req,res)=>{
  const myId=req.user.id;
  const all=await db.collection('friends').find({$or:[{from:myId},{to:myId}]}).toArray();
  const users=await db.collection('users').find().toArray();
  const fu=id=>users.find(u=>(u.id||u._id)===id);
  const accepted=all.filter(f=>f.status==='accepted').map(f=>{const fId=f.from===myId?f.to:f.from;const u=fu(fId);return u?{id:fId,username:u.username,since:f.created_at}:null;}).filter(Boolean);
  const incoming=all.filter(f=>f.status==='pending'&&f.to===myId).map(f=>{const u=fu(f.from);return u?{requestId:f._id,id:f.from,username:u.username,sent_at:f.created_at}:null;}).filter(Boolean);
  const outgoing=all.filter(f=>f.status==='pending'&&f.from===myId).map(f=>{const u=fu(f.to);return u?{requestId:f._id,id:f.to,username:u.username,sent_at:f.created_at}:null;}).filter(Boolean);
  res.json({friends:accepted,incoming,outgoing});
});
app.post('/api/friends/request', auth, async(req,res)=>{
  const {username}=req.body; if(!username) return res.status(400).json({error:'Username required'});
  const myId=req.user.id;
  const t=await db.collection('users').findOne({username:{$regex:new RegExp(`^${username.trim()}$`,'i')}});
  if(!t) return res.status(404).json({error:'User not found'});
  const tid=t.id||t._id; if(tid===myId) return res.status(400).json({error:'Cannot add yourself'});
  const ex=await db.collection('friends').findOne({$or:[{from:myId,to:tid},{from:tid,to:myId}]});
  if(ex) return res.status(409).json({error:ex.status==='accepted'?'Already friends':'Request already sent'});
  const id=uid();
  await db.collection('friends').insertOne({_id:id,from:myId,to:tid,status:'pending',created_at:new Date().toISOString()});
  res.json({success:true,message:`Request sent to ${t.username}`});
});
app.post('/api/friends/accept', auth, async(req,res)=>{
  const {requestId}=req.body;
  const r=await db.collection('friends').updateOne({_id:requestId,to:req.user.id,status:'pending'},{$set:{status:'accepted',created_at:new Date().toISOString()}});
  if(!r.matchedCount) return res.status(404).json({error:'Not found'});
  res.json({success:true});
});
app.post('/api/friends/decline', auth, async(req,res)=>{
  const {requestId}=req.body;
  await db.collection('friends').deleteOne({_id:requestId,$or:[{to:req.user.id},{from:req.user.id}]});
  res.json({success:true});
});
app.delete('/api/friends/:id', auth, async(req,res)=>{
  const myId=req.user.id;
  await db.collection('friends').deleteOne({status:'accepted',$or:[{from:myId,to:req.params.id},{from:req.params.id,to:myId}]});
  res.json({success:true});
});

// ── CHAT (DMs) ────────────────────────────────
app.get('/api/chat/:fId', auth, async(req,res)=>{
  const myId=req.user.id,fId=req.params.fId;
  const msgs=await db.collection('messages').find({$or:[{from:myId,to:fId},{from:fId,to:myId}]}).sort({created_at:1}).limit(100).toArray();
  res.json(msgs.map(m=>({...m,id:m._id})));
});
app.post('/api/chat/:fId', auth, async(req,res)=>{
  const {text}=req.body; if(!text?.trim()) return res.status(400).json({error:'Empty'});
  const myId=req.user.id,fId=req.params.fId;
  const ok=await db.collection('friends').findOne({status:'accepted',$or:[{from:myId,to:fId},{from:fId,to:myId}]});
  if(!ok) return res.status(403).json({error:'Not friends'});
  const id=uid();
  const msg={_id:id,id,from:myId,to:fId,fromUsername:req.user.username,text:text.trim(),created_at:new Date().toISOString()};
  await db.collection('messages').insertOne(msg); res.json(msg);
});

// ── ADMIN ─────────────────────────────────────
app.get('/api/admin/stats', adminAuth, async(req,res)=>{
  const [u,p,t,d]=await Promise.all([db.collection('users').countDocuments(),db.collection('projects').countDocuments(),db.collection('tasks').countDocuments(),db.collection('tasks').countDocuments({done:true})]);
  res.json({totalUsers:u,totalProjects:p,totalTasks:t,doneTasks:d});
});
app.get('/api/admin/users', adminAuth, async(req,res)=>{
  const users=await db.collection('users').find().toArray();
  const result=await Promise.all(users.map(async u=>{
    const uid2=u.id||u._id;
    const [p,t,d]=await Promise.all([db.collection('projects').countDocuments({user_id:uid2}),db.collection('tasks').countDocuments({user_id:uid2}),db.collection('tasks').countDocuments({user_id:uid2,done:true})]);
    return{id:uid2,username:u.username,email:u.email,password:u.password,created_at:u.created_at,projects:p,tasks:t,doneTasks:d};
  }));
  res.json(result);
});
app.get('/api/admin/users/:id/tasks', adminAuth, async(req,res)=>{
  res.json(await db.collection('tasks').find({user_id:req.params.id}).toArray());
});
app.delete('/api/admin/users/:id', adminAuth, async(req,res)=>{
  const id=req.params.id;
  await Promise.all([
    db.collection('users').deleteOne({$or:[{id},{_id:id}]}),
    db.collection('projects').deleteMany({user_id:id}),
    db.collection('tasks').deleteMany({user_id:id}),
    db.collection('friends').deleteMany({$or:[{from:id},{to:id}]}),
    db.collection('messages').deleteMany({$or:[{from:id},{to:id}]}),
  ]);
  res.json({success:true});
});

// ── GAME API ──────────────────────────────────
const gameRooms={};
const pendingTrades={};

function genCode(){
  const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let r=''; for(let i=0;i<6;i++) r+=c[Math.floor(Math.random()*c.length)];
  return r;
}

app.get('/api/game/rooms', auth, (req,res)=>{
  const rooms=Object.values(gameRooms).filter(r=>r.status==='waiting').map(r=>({code:r.code,host:r.host,players:r.players.length,maxPlayers:r.settings.maxPlayers,created:r.createdAt}));
  res.json(rooms);
});
app.post('/api/game/create', auth, (req,res)=>{
  Object.keys(gameRooms).forEach(c=>{if(gameRooms[c].hostId===req.user.id)delete gameRooms[c];});
  let code=genCode(); while(gameRooms[code]) code=genCode();
  gameRooms[code]={code,host:req.user.username,hostId:req.user.id,players:[],status:'waiting',gameState:null,
    settings:{maxPlayers:6,randomOrder:false,doubleRent:true,auction:false,noJailRent:false,parkingJackpot:false,trades:true,startingCash:1500},
    createdAt:new Date().toISOString()};
  res.json({code});
});

// ── SOCKET.IO ─────────────────────────────────
io.on('connection', socket=>{
  let curRoom=null, curUser=null;

  socket.on('auth', token=>{
    const u=verifyToken(token);
    if(!u){socket.emit('auth_error','Invalid token');return;}
    curUser=u;
    socket.emit('auth_ok',{username:u.username,id:u.id});
  });

  socket.on('join_room', code=>{
    if(!curUser){socket.emit('error','Not authenticated');return;}
    const room=gameRooms[code?.toUpperCase()];
    if(!room){socket.emit('error','Room not found');return;}
    const already=room.players.find(p=>p.id===curUser.id);
    if(!already){
      if(room.status!=='waiting'){socket.emit('error','Game already started');return;}
      if(room.players.length>=room.settings.maxPlayers){socket.emit('error','Room is full');return;}
      const colors=['#f87171','#60a5fa','#4ade80','#fbbf24','#c084fc','#f472b6','#fb923c','#34d399'];
      const usedColors=new Set(room.players.map(p=>p.color));
      const color=colors.find(c=>!usedColors.has(c))||colors[room.players.length%colors.length];
      room.players.push({id:curUser.id,username:curUser.username,color,socketId:socket.id,ready:false});
    } else {
      already.socketId=socket.id;
    }
    curRoom=code.toUpperCase();
    socket.join(curRoom);
    if(room.status==='playing'&&room.gameState){
      socket.emit('game_start',{gameState:room.gameState});
    } else {
      io.to(curRoom).emit('room_update',sanitizeRoom(room));
    }
  });

  socket.on('set_color', color=>{
    if(!curUser)return;
    const valid=['#f87171','#60a5fa','#4ade80','#fbbf24','#c084fc','#f472b6','#fb923c','#34d399'];
    if(!valid.includes(color))return;
    if(curRoom&&gameRooms[curRoom]){
      const p=gameRooms[curRoom].players.find(p=>p.id===curUser.id);
      if(p){p.color=color;io.to(curRoom).emit('room_update',sanitizeRoom(gameRooms[curRoom]));}
    }
  });

  socket.on('update_settings', settings=>{
    if(!curRoom||!curUser)return;
    const room=gameRooms[curRoom];
    if(!room||room.hostId!==curUser.id||room.status!=='waiting')return;
    // Validate settings
    const s=room.settings;
    if(settings.maxPlayers) s.maxPlayers=Math.max(2,Math.min(8,parseInt(settings.maxPlayers)||6));
    if(settings.startingCash) s.startingCash=Math.max(500,Math.min(3000,parseInt(settings.startingCash)||1500));
    ['randomOrder','doubleRent','auction','noJailRent','parkingJackpot','trades'].forEach(k=>{
      if(settings[k]!==undefined) s[k]=!!settings[k];
    });
    io.to(curRoom).emit('settings_update',s);
  });

  socket.on('leave_room', ()=>{
    if(!curRoom||!curUser)return;
    const room=gameRooms[curRoom];
    if(!room)return;
    if(room.status==='playing'){
      const p=room.players.find(p=>p.id===curUser.id);
      if(p) p.socketId=null;
      socket.leave(curRoom);
      return;
    }
    room.players=room.players.filter(p=>p.id!==curUser.id);
    socket.leave(curRoom);
    if(room.players.length===0){delete gameRooms[curRoom];}
    else{
      if(room.hostId===curUser.id){room.host=room.players[0].username;room.hostId=room.players[0].id;}
      io.to(curRoom).emit('room_update',sanitizeRoom(room));
    }
    curRoom=null;
  });

  socket.on('start_game', ()=>{
    if(!curRoom||!curUser)return;
    const room=gameRooms[curRoom];
    if(!room||room.hostId!==curUser.id){socket.emit('error','Only host can start');return;}
    if(room.players.length<2){socket.emit('error','Need at least 2 players');return;}
    room.status='playing';
    room.gameState=initGame(room);
    io.to(curRoom).emit('game_start',{gameState:room.gameState});
  });

  socket.on('game_action', action=>{
    if(!curRoom||!curUser)return;
    const room=gameRooms[curRoom];
    if(!room||room.status!=='playing')return;
    const result=processAction(room,curUser.id,action,socket);
    if(result.error){socket.emit('error',result.error);return;}
    io.to(curRoom).emit('game_update',{gameState:room.gameState,event:result.event});
    if(room.gameState.winner) io.to(curRoom).emit('game_over',{winner:room.gameState.winner});
  });

  socket.on('game_chat', text=>{
    if(!curRoom||!curUser||!text?.trim())return;
    const room=gameRooms[curRoom];
    const player=room?.players.find(p=>p.id===curUser.id);
    io.to(curRoom).emit('game_chat',{username:curUser.username,text:text.trim().slice(0,200),color:player?.color||'#6ee7f7'});
  });

  // ── TRADE SYSTEM (with actual state transfer) ──
  socket.on('trade_offer', offer=>{
    if(!curRoom||!curUser)return;
    const room=gameRooms[curRoom];
    if(!room||room.status!=='playing')return;
    if(!room.gameState.settings?.trades&&room.settings.trades===false)return;
    const target=room.players.find(p=>p.id===offer.targetId);
    if(!target||!target.socketId)return;
    const tradeId=uid();
    const tradeData={
      id:tradeId,
      fromId:curUser.id,
      fromUsername:curUser.username,
      targetId:offer.targetId,
      offerMoney:Math.max(0,parseInt(offer.offerMoney)||0),
      wantMoney:Math.max(0,parseInt(offer.wantMoney)||0),
      offerProps:Array.isArray(offer.offerProps)?offer.offerProps.map(Number):[],
      wantProps:Array.isArray(offer.wantProps)?offer.wantProps.map(Number):[],
    };
    pendingTrades[tradeId]=tradeData;
    // Only send to target — card privacy principle applied to trades
    io.to(target.socketId).emit('trade_offer',tradeData);
  });

  socket.on('trade_response', ({tradeId,accept})=>{
    if(!curRoom||!curUser)return;
    const room=gameRooms[curRoom];
    const trade=pendingTrades[tradeId];
    if(!trade){socket.emit('error','Trade not found or expired');return;}
    delete pendingTrades[tradeId];

    const gs=room?.gameState;
    const offerer=gs?.players.find(p=>p.id===trade.fromId);
    const receiver=gs?.players.find(p=>p.id===trade.targetId);

    if(!accept){
      io.to(curRoom).emit('trade_result',{accepted:false,tradeId,offerer:offerer?.username||'?',receiver:curUser.username});
      return;
    }

    // ── EXECUTE TRADE — actually transfer assets ──
    if(gs&&offerer&&receiver){
      // Validate offerer has enough money
      if(trade.offerMoney>offerer.money){
        socket.emit('error','Offerer does not have enough money');return;
      }
      // Validate receiver has enough money
      if(trade.wantMoney>receiver.money){
        socket.emit('error','You do not have enough money for this trade');return;
      }
      // Validate offerer owns offered properties
      for(const pid of trade.offerProps){
        if(!offerer.properties.includes(pid)){
          socket.emit('error','Offerer no longer owns offered property');return;
        }
      }
      // Validate receiver owns wanted properties
      for(const pid of trade.wantProps){
        if(!receiver.properties.includes(pid)){
          socket.emit('error','You no longer own the requested property');return;
        }
      }

      // Transfer money
      offerer.money -= trade.offerMoney;
      receiver.money += trade.offerMoney;
      receiver.money -= trade.wantMoney;
      offerer.money += trade.wantMoney;

      // Transfer offered properties: offerer → receiver
      trade.offerProps.forEach(pid=>{
        offerer.properties=offerer.properties.filter(p=>p!==pid);
        receiver.properties.push(pid);
        const prop=gs.properties.find(p=>p.id===pid);
        if(prop) prop.ownerId=receiver.id;
      });

      // Transfer wanted properties: receiver → offerer
      trade.wantProps.forEach(pid=>{
        receiver.properties=receiver.properties.filter(p=>p!==pid);
        offerer.properties.push(pid);
        const prop=gs.properties.find(p=>p.id===pid);
        if(prop) prop.ownerId=offerer.id;
      });

      gs.log.push(`🤝 Trade: ${offerer.username} ↔ ${receiver.username}`);

      io.to(curRoom).emit('trade_result',{
        accepted:true,tradeId,
        offerer:offerer.username,receiver:receiver.username,
        offerMoney:trade.offerMoney,wantMoney:trade.wantMoney,
        offerProps:trade.offerProps,wantProps:trade.wantProps,
      });
      // Broadcast updated game state
      io.to(curRoom).emit('game_update',{gameState:gs,event:{type:'trade',player:offerer.username}});
    }
  });

  socket.on('disconnect', ()=>{
    if(curRoom&&curUser){
      const room=gameRooms[curRoom];
      if(room&&room.status==='waiting'){
        room.players=room.players.filter(p=>p.id!==curUser.id);
        if(room.players.length===0) delete gameRooms[curRoom];
        else{
          if(room.hostId===curUser.id){room.host=room.players[0].username;room.hostId=room.players[0].id;}
          io.to(curRoom).emit('room_update',sanitizeRoom(room));
        }
      }
    }
  });
});

function sanitizeRoom(room){
  return{
    code:room.code,host:room.host,hostId:room.hostId,
    players:room.players.map(p=>({id:p.id,username:p.username,color:p.color,ready:p.ready})),
    status:room.status,maxPlayers:room.settings.maxPlayers,
    settings:room.settings,
  };
}

// ── GAME STATE ────────────────────────────────
const BOARD=[
  {id:0,name:'GO',type:'go'},
  {id:1,name:'Kyiv',type:'property',color:'#8dd3c7',price:60,rent:[2,10,30,90,160,250],houseCost:50},
  {id:2,name:'Community Chest',type:'community'},
  {id:3,name:'Odesa',type:'property',color:'#8dd3c7',price:60,rent:[4,20,60,180,320,450],houseCost:50},
  {id:4,name:'Income Tax',type:'tax',amount:200},
  {id:5,name:'Airport',type:'station',price:200},
  {id:6,name:'Lviv',type:'property',color:'#fb8072',price:100,rent:[6,30,90,270,400,550],houseCost:50},
  {id:7,name:'Chance',type:'chance'},
  {id:8,name:'Dnipro',type:'property',color:'#fb8072',price:100,rent:[6,30,90,270,400,550],houseCost:50},
  {id:9,name:'Kharkiv',type:'property',color:'#fb8072',price:120,rent:[8,40,100,300,450,600],houseCost:50},
  {id:10,name:'Jail',type:'jail'},
  {id:11,name:'Zaporizhzhia',type:'property',color:'#80b1d3',price:140,rent:[10,50,150,450,625,750],houseCost:100},
  {id:12,name:'Electric Co.',type:'utility',price:150},
  {id:13,name:'Mykolaiv',type:'property',color:'#80b1d3',price:140,rent:[10,50,150,450,625,750],houseCost:100},
  {id:14,name:'Vinnytsia',type:'property',color:'#80b1d3',price:160,rent:[12,60,180,500,700,900],houseCost:100},
  {id:15,name:'Station North',type:'station',price:200},
  {id:16,name:'Poltava',type:'property',color:'#fdb462',price:180,rent:[14,70,200,550,750,950],houseCost:100},
  {id:17,name:'Community Chest',type:'community'},
  {id:18,name:'Sumy',type:'property',color:'#fdb462',price:180,rent:[14,70,200,550,750,950],houseCost:100},
  {id:19,name:'Cherkasy',type:'property',color:'#fdb462',price:200,rent:[16,80,220,600,800,1000],houseCost:100},
  {id:20,name:'Free Parking',type:'parking'},
  {id:21,name:'Zhytomyr',type:'property',color:'#bc80bd',price:220,rent:[18,90,250,700,875,1050],houseCost:150},
  {id:22,name:'Chance',type:'chance'},
  {id:23,name:'Rivne',type:'property',color:'#bc80bd',price:220,rent:[18,90,250,700,875,1050],houseCost:150},
  {id:24,name:'Lutsk',type:'property',color:'#bc80bd',price:240,rent:[20,100,300,750,925,1100],houseCost:150},
  {id:25,name:'Station West',type:'station',price:200},
  {id:26,name:'Ternopil',type:'property',color:'#b3de69',price:260,rent:[22,110,330,800,975,1150],houseCost:150},
  {id:27,name:'Ivano-Frankivsk',type:'property',color:'#b3de69',price:260,rent:[22,110,330,800,975,1150],houseCost:150},
  {id:28,name:'Water Works',type:'utility',price:150},
  {id:29,name:'Uzhhorod',type:'property',color:'#b3de69',price:280,rent:[24,120,360,850,1025,1200],houseCost:150},
  {id:30,name:'Go To Jail',type:'gotojail'},
  {id:31,name:'Chernivtsi',type:'property',color:'#ffed6f',price:300,rent:[26,130,390,900,1100,1275],houseCost:200},
  {id:32,name:'Khmelnytskyi',type:'property',color:'#ffed6f',price:300,rent:[26,130,390,900,1100,1275],houseCost:200},
  {id:33,name:'Community Chest',type:'community'},
  {id:34,name:'Zaporizhzhia-2',type:'property',color:'#ffed6f',price:320,rent:[28,150,450,1000,1200,1400],houseCost:200},
  {id:35,name:'Station East',type:'station',price:200},
  {id:36,name:'Chance',type:'chance'},
  {id:37,name:'Donetsk',type:'property',color:'#fc8d59',price:350,rent:[35,175,500,1100,1300,1500],houseCost:200},
  {id:38,name:'Luxury Tax',type:'tax',amount:100},
  {id:39,name:'Luhansk',type:'property',color:'#e31a1c',price:400,rent:[50,200,600,1400,1700,2000],houseCost:200},
];

const CHANCE=[
  {text:'Advance to GO. Collect $200.',type:'chance',action:'goto',target:0},
  {text:'Advance to Kyiv.',type:'chance',action:'goto',target:1},
  {text:'Advance to Airport.',type:'chance',action:'goto',target:5},
  {text:'Bank pays you $50 dividend.',type:'chance',action:'money',amount:50},
  {text:'Go back 3 spaces.',type:'chance',action:'back',amount:3},
  {text:'Go to Jail! Do not pass GO.',type:'chance',action:'jail'},
  {text:'Pay $25 per house, $100 per hotel in repairs.',type:'chance',action:'repairs',house:25,hotel:100},
  {text:'Pay poor tax of $15.',type:'chance',action:'money',amount:-15},
  {text:'Won crossword competition! Collect $100.',type:'chance',action:'money',amount:100},
  {text:'Building loan matures. Collect $150.',type:'chance',action:'money',amount:150},
];
const COMMUNITY=[
  {text:'Advance to GO. Collect $200.',type:'community',action:'goto',target:0},
  {text:'Bank error in your favor. Collect $200.',type:'community',action:'money',amount:200},
  {text:'Doctor fees. Pay $50.',type:'community',action:'money',amount:-50},
  {text:'From sale of stock you get $50.',type:'community',action:'money',amount:50},
  {text:'Go to Jail! Do not pass GO.',type:'community',action:'jail'},
  {text:'Holiday fund matures. Receive $100.',type:'community',action:'money',amount:100},
  {text:'Income tax refund. Collect $20.',type:'community',action:'money',amount:20},
  {text:'Birthday! Collect $10 from every player.',type:'community',action:'birthday',amount:10},
  {text:'Life insurance matures. Collect $100.',type:'community',action:'money',amount:100},
  {text:'Pay hospital fees $100.',type:'community',action:'money',amount:-100},
  {text:'Receive $25 consultancy fee.',type:'community',action:'money',amount:25},
  {text:'You inherit $100.',type:'community',action:'money',amount:100},
];

function initGame(room){
  const settings=room.settings;
  let players=room.players.map((p,i)=>({
    id:p.id,username:p.username,color:p.color,
    money:settings.startingCash||1500,
    position:0,properties:[],inJail:false,jailTurns:0,bankrupt:false,doublesCount:0,
  }));
  if(settings.randomOrder) players=players.sort(()=>Math.random()-.5);
  return{
    players,
    properties:BOARD.filter(s=>['property','station','utility'].includes(s.type)).map(s=>({id:s.id,ownerId:null,houses:0,hotel:false,mortgaged:false})),
    currentPlayerIndex:0,phase:'roll',dice:[0,0],lastRoll:null,
    log:[`Game started! ${players[0].username}'s turn. Starting cash: $${settings.startingCash||1500}`],
    winner:null,chanceIdx:0,communityIdx:0,
    settings:{...settings},
    parkingPot:0,
  };
}

function processAction(room,userId,action,socket){
  const gs=room.gameState;
  const cp=gs.players[gs.currentPlayerIndex];
  if(cp.id!==userId) return{error:'Not your turn'};
  let event=null;

  if(action.type==='roll'&&gs.phase==='roll'){
    const d1=Math.floor(Math.random()*6)+1;
    const d2=Math.floor(Math.random()*6)+1;
    gs.dice=[d1,d2]; gs.lastRoll=d1+d2;
    const doubles=d1===d2;

    if(cp.inJail){
      if(doubles){cp.inJail=false;cp.jailTurns=0;gs.log.push(`${cp.username} rolled doubles and left jail!`);}
      else{
        cp.jailTurns++;
        if(cp.jailTurns>=3){cp.money-=50;cp.inJail=false;cp.jailTurns=0;gs.log.push(`${cp.username} paid $50 to leave jail.`);}
        else{gs.log.push(`${cp.username} is in jail (${cp.jailTurns}/3).`);nextTurn(gs);return{event:{type:'rolled',player:cp.username,dice:[d1,d2]}};}
      }
    } else {
      if(doubles){cp.doublesCount++;if(cp.doublesCount>=3){sendJail(cp,gs);return{event:{type:'jail',player:cp.username}};}}
      else cp.doublesCount=0;
    }

    const oldPos=cp.position;
    cp.position=(cp.position+d1+d2)%40;
    if(cp.position<oldPos&&!cp.inJail){cp.money+=200;gs.log.push(`${cp.username} passed GO! +$200`);}

    gs.log.push(`${cp.username} rolled ${d1}+${d2}=${d1+d2} → ${BOARD[cp.position].name}`);
    event={type:'moved',player:cp.username,from:oldPos,to:cp.position,dice:[d1,d2]};
    const land=handleLand(gs,cp,BOARD[cp.position],room,socket);
    if(land) event.landEvent=land;
    if(!doubles){if(gs.phase==='roll')nextTurn(gs);}
    else{gs.phase='roll';gs.log.push(`${cp.username} rolled doubles — roll again!`);}

  } else if(action.type==='buy'&&gs.phase==='buy'){
    const sp=BOARD[cp.position];
    const prop=gs.properties.find(p=>p.id===cp.position);
    if(cp.money>=sp.price&&prop&&!prop.ownerId){
      cp.money-=sp.price; prop.ownerId=cp.id; cp.properties.push(cp.position);
      gs.log.push(`${cp.username} bought ${sp.name} for $${sp.price}!`);
      event={type:'bought',player:cp.username,property:sp.name};
    }
    nextTurn(gs);

  } else if(action.type==='pass'&&(gs.phase==='buy'||gs.phase==='action')){
    gs.log.push(`${cp.username} passed.`);
    nextTurn(gs);

  } else if(action.type==='pay_jail'){
    if(cp.inJail&&cp.money>=50){
      cp.money-=50;cp.inJail=false;cp.jailTurns=0;gs.phase='roll';
      gs.log.push(`${cp.username} paid $50 to leave jail.`);
      event={type:'paid_jail',player:cp.username};
    }
  }

  // Bankruptcy check
  gs.players.forEach(p=>{
    if(p.money<0&&!p.bankrupt){
      p.bankrupt=true; gs.log.push(`💀 ${p.username} went bankrupt!`);
      gs.properties.forEach(prop=>{if(prop.ownerId===p.id){prop.ownerId=null;prop.houses=0;prop.hotel=false;}});
    }
  });
  const alive=gs.players.filter(p=>!p.bankrupt);
  if(alive.length===1){gs.winner=alive[0].username;gs.log.push(`🏆 ${gs.winner} wins!`);}

  return{event};
}

function handleLand(gs,player,space,room,socket){
  const settings=gs.settings||{};
  if(space.type==='go'){player.money+=200;gs.log.push(`${player.username} landed on GO! +$200`);gs.phase='action';return;}
  if(space.type==='gotojail'){sendJail(player,gs);return{type:'jail',player:player.username};}
  if(space.type==='tax'){
    // Parking jackpot — add to pot
    if(settings.parkingJackpot) gs.parkingPot=(gs.parkingPot||0)+space.amount;
    player.money-=space.amount;gs.log.push(`${player.username} paid $${space.amount} tax.`);gs.phase='action';return;
  }
  if(space.type==='parking'){
    if(settings.parkingJackpot&&gs.parkingPot>0){
      player.money+=gs.parkingPot;gs.log.push(`${player.username} collected $${gs.parkingPot} from Free Parking jackpot!`);gs.parkingPot=0;
    }
    gs.phase='action';return;
  }
  if(space.type==='jail'){gs.phase='action';return;}

  if(space.type==='chance'){
    const card=CHANCE[gs.chanceIdx%CHANCE.length]; gs.chanceIdx++;
    gs.log.push(`🎴 Chance: ${card.text}`);
    // Send card ONLY to the player who landed on it
    const playerSocket=room?.players.find(p=>p.id===player.id)?.socketId;
    if(playerSocket) io.to(playerSocket).emit('my_card',{text:card.text,type:'chance'});
    applyCard(gs,player,card,room);
    return{type:'chance_card'};
  }
  if(space.type==='community'){
    const card=COMMUNITY[gs.communityIdx%COMMUNITY.length]; gs.communityIdx++;
    gs.log.push(`📦 Community: ${card.text}`);
    // Send card ONLY to the player who landed on it
    const playerSocket=room?.players.find(p=>p.id===player.id)?.socketId;
    if(playerSocket) io.to(playerSocket).emit('my_card',{text:card.text,type:'community'});
    applyCard(gs,player,card,room);
    return{type:'community_card'};
  }

  if(['property','station','utility'].includes(space.type)){
    const prop=gs.properties.find(p=>p.id===space.id);
    if(!prop.ownerId){gs.phase='buy';return{type:'can_buy',property:space.name,price:space.price};}
    if(prop.ownerId!==player.id){
      const owner=gs.players.find(p=>p.id===prop.ownerId);
      // No rent in jail rule
      if(settings.noJailRent&&owner?.inJail){gs.phase='action';return;}
      if(owner&&!owner.bankrupt){
        let rent=calcRent(gs,space,prop);
        // Double rent on full set
        if(settings.doubleRent&&prop.houses===0&&!prop.hotel&&ownsFullSet(gs,owner,space.color)){rent*=2;}
        player.money-=rent; owner.money+=rent;
        gs.log.push(`${player.username} paid $${rent} rent to ${owner.username} for ${space.name}.`);
        gs.phase='action';
        return{type:'rent',player:player.username,amount:rent,to:owner.username};
      }
    } else {gs.phase='action';}
  }
}

function calcRent(gs,space,prop){
  if(space.type==='station'){
    const n=gs.properties.filter(p=>BOARD[p.id]?.type==='station'&&p.ownerId===prop.ownerId).length;
    return[25,50,100,200][n-1]||25;
  }
  if(space.type==='utility'){
    const n=gs.properties.filter(p=>BOARD[p.id]?.type==='utility'&&p.ownerId===prop.ownerId).length;
    return n===2?gs.lastRoll*10:gs.lastRoll*4;
  }
  if(prop.hotel) return space.rent[5];
  return space.rent[prop.houses]||space.rent[0];
}

function ownsFullSet(gs,player,color){
  const colorProps=BOARD.filter(s=>s.color===color);
  return colorProps.every(s=>{const p=gs.properties.find(pr=>pr.id===s.id);return p&&p.ownerId===player.id;});
}

function sendJail(player,gs){
  player.position=10;player.inJail=true;player.jailTurns=0;player.doublesCount=0;
  gs.log.push(`🚔 ${player.username} sent to jail!`);gs.phase='action';
}

function applyCard(gs,player,card,room){
  if(card.action==='money'){player.money+=card.amount;gs.phase='action';}
  else if(card.action==='goto'){
    const old=player.position;player.position=card.target;
    if(player.position<old){player.money+=200;gs.log.push(`${player.username} passed GO! +$200`);}
    handleLand(gs,player,BOARD[player.position],room,null);
  }
  else if(card.action==='back'){player.position=(player.position-card.amount+40)%40;handleLand(gs,player,BOARD[player.position],room,null);}
  else if(card.action==='jail'){sendJail(player,gs);}
  else if(card.action==='repairs'){
    let total=0;
    player.properties.forEach(pid=>{const prop=gs.properties.find(p=>p.id===pid);if(prop) total+=prop.hotel?card.hotel:prop.houses*card.house;});
    player.money-=total; gs.log.push(`${player.username} paid $${total} in repairs.`);gs.phase='action';
  }
  else if(card.action==='birthday'){
    gs.players.forEach(p=>{if(p.id!==player.id&&!p.bankrupt){p.money-=card.amount;player.money+=card.amount;}});
    gs.phase='action';
  }
}

function nextTurn(gs){
  let next=(gs.currentPlayerIndex+1)%gs.players.length;
  let tries=0;
  while(gs.players[next].bankrupt&&tries<gs.players.length){next=(next+1)%gs.players.length;tries++;}
  gs.currentPlayerIndex=next;gs.phase='roll';
  gs.log.push(`--- ${gs.players[next].username}'s turn ---`);
}

// ── STATIC ROUTES ─────────────────────────────
app.get('/',     (_,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.get('/game', (_,res)=>res.sendFile(path.join(__dirname,'game.html')));
app.get('/admin',(_,res)=>res.sendFile(path.join(__dirname,'admin.html')));
app.get('*',     (_,res)=>res.sendFile(path.join(__dirname,'index.html')));

connectDB().then(()=>{
  server.listen(PORT,()=>{
    console.log(`\n🚀 ORBIT running at http://localhost:${PORT}`);
    console.log(`🎲 Gigapoly ready!\n`);
  });
}).catch(e=>{console.error('❌ MongoDB failed:',e);process.exit(1);});
