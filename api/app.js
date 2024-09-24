require ('dotenv').config()
const express = require ('express')
const cors = require('cors')
const mongoose = require ('mongoose')
const bcrypt = require ('bcryptjs')
const jwt = require('jsonwebtoken')

const app = express()

// Configura o CORS
app.use(cors());

// Configurando o express para ler Json
app.use(express.json())


//Modelos
const User = require('../modelos/User')



// Open route
app.get('/', (req, res) =>{
    res.status(200).json({msg: 'bem vindo a nossa api!'})
})



//Private Route
app.get('/user/:id',checktoken, async (req,res) =>{


    const id= req.params.id

    //Checkar se o usuário existe
    const user = await User.findById(id, '-password')
    
    if(!user){
        return res.status(404).json({msg:"Usuário não existe"})
    }

    res.status(200).json({user})
    })

    function checktoken(req, res, next){

        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(" ")[1]

        if(!token){
            return res.status(401).json({msg:"acesso negado"})
        }

        //Validar se o Token está correto

        try{

            const secret = process.env.SECRET
            jwt.verify(token, secret)

            next()

        }catch(error){
            res.status(400).json({msg:"Token Inválido"})
        }
    }



// Registrando usuário
app.post('/auth/register', async (req, res) =>{

    const { name, email, password, confirmPassword } = req.body

    // validações 
    if (!name){
        return res.status(422).json({msg : 'O nome é obrigatório'})
    }

    if (!email){
        return res.status(422).json({msg : 'O email é obrigatório'})
    }

    if (!password){
        return res.status(422).json({msg : 'A senha é obrigatório'})
    }

    if (password !== confirmPassword){
        return res.status(422).json({msg : 'As senhas não conferem'})
    }

// Checar se o Usuário existe
const userExist = await User.findOne({email:email})

if(userExist){
    return res.status(422).json({msg : 'Utilize outro email'})
}

// Criando password e segurança
const salt = await bcrypt.genSalt(12)
const passwordHash = await bcrypt.hash(password, salt)

// Criando Usuário
const user = new User({
    name,
    email,
    password: passwordHash,
})

try{

    await user.save()
    res.status(210).json({msg :"Usuário criado com sucesso"})

} catch(error) {
    console.log(error)
    res.status(500).json({msg: "Tente mais tarde"})
}



})

//Login Usuário
app.post("/auth/login", async (req, res) =>{
    console.log(req.body)
    
    const {email, password} = req.body


    //Validação
    if (!email){
        return res.status(422).json({msg : 'O email é obrigatório'})
    }

    if (!password){
        return res.status(422).json({msg : 'A senha é obrigatório'})
    }

    //Checar se Usuário existe
    const user = await User.findOne({email: email})
    if(!user){
    return res.status(422).json({msg : 'usuário não encontrado'})
    }

    //Checar se a senha é valida
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({msg : 'A senha esta errada'})
    }

try{

    const secret = process.env.SECRET

    const token = jwt.sign({
        id: user._id,
    }, 
    secret, 
)

res.status(200).json({msg:"autenticado com sucesso", token, name: user.name})


}catch(error) {
    console.log(error)
    res.status(500).json({msg: "Tente mais tarde"})
}

})

// Credenciais para conectar ao DB
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS
const dbUri = process.env.MONGODB_URI;

// Opções de conexão para pooling
const options = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10, // Tamanho máximo do pool de conexões
  };

mongoose.connect(dbUri)
  .then(() => {
    // app.listen(3000)
    console.log('Conectado ao MongoDB')})
  .catch((error) => console.error('Erro ao conectar ao MongoDB:', error));

module.exports = app;