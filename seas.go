//Simple go as an encryption service


package main

import (
    "encoding/base64"
    "fmt"
	"context"
    "github.com/richard-lyman/lithcrypt"
	"os"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
	"encoding/pem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
)

func main() {
	
    // payload := []byte("ThisisSecre333t")
	// password := []byte("P@ssw0rd")
	initKeyRings()
	
	mw := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte("OLsccJOxxVX3678gFd2UG82cSzjS"), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	r := mux.NewRouter()
	ar := mux.NewRouter()
	r.HandleFunc("/api/encrypt", encryptText)
	r.HandleFunc("/api/encryptrsa", HandlerEncryptRSA)
	ar.HandleFunc("/api/decrypt", decryptText)
	ar.HandleFunc("/api/encryptb64", encodeb64Text)
	http.Handle("/", ar)

	an := negroni.New(negroni.HandlerFunc(mw.HandlerWithNext), negroni.Wrap(ar))
	r.PathPrefix("/api").Handler(an)
	
	n := negroni.Classic()
	n.UseHandler(r)
	n.Run(":7080")
}

func encryptText(w http.ResponseWriter, r *http.Request){
	plaintext := r.FormValue("plaintext")
	chiper := r.FormValue("chiper")
	w.WriteHeader(http.StatusOK)
	encrypted, encrypt_error := lithcrypt.Encrypt([]byte(chiper), []byte(plaintext))
    if encrypt_error != nil {
        fmt.Println("Failed to encrypt:", encrypt_error)
        os.Exit(1)
    }
	fmt.Fprintf(w, encodebase64(encrypted))
}

func decryptText(w http.ResponseWriter, r *http.Request){
	encrypted := r.FormValue("encrypted")
	chiper := r.FormValue("chiper")
	bytes_text := decodebase64(encrypted)

    original, decrypt_error := lithcrypt.Decrypt([]byte(chiper), []byte(bytes_text))
    if decrypt_error != nil {
        fmt.Println("Failed to decrypt:", decrypt_error)
        os.Exit(1)
	}
    fmt.Fprintf(w, string(original))
}

// func encryptText(w http.ResponseWriter, r *http.Request){
// 	vars:=mux.Vars(r)
// 	w.WriteHeader(http.StatusOK)
// 	encrypted, encrypt_error := lithcrypt.Encrypt([]byte(vars["chiper"]), []byte(vars["plaintext"]))
//     if encrypt_error != nil {
//         fmt.Println("Failed to encrypt:", encrypt_error)
//         os.Exit(1)
//     }
// 	fmt.Fprintf(w, encodebase64(encrypted))
// }

func encodeb64Text(w http.ResponseWriter, ar *http.Request){
	vars:=mux.Vars(ar)
	w.WriteHeader(http.StatusOK)
	encodebase64 := base64.StdEncoding.EncodeToString([]byte(vars["plaintext"]))
	fmt.Fprintf(w, encodebase64)
}

func initKeyRings() {
	projectID := "styletheory-1254"
	locationID := "asia-southeast1"

	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}

	kmsService, err := cloudkms.New(client)
	if err != nil {
		log.Fatal(err)
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s", projectID, locationID)
	response, err := kmsService.Projects.Locations.KeyRings.List(parentName).Do()
	if err != nil {
		log.Fatalf("Failed to list key rings: %v", err)
	}
	
	for _, keyRing := range response.KeyRings {
		fmt.Printf("KeyRing: %q\n", keyRing.Name)
	}
}

func getAsymmetricPublicKey(ctx context.Context, client *cloudkms.Service, keyPath string) (interface{}, error) {
	response, err := client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(keyPath).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %+v", err)
	}
	keyBytes := []byte(response.Pem)
	block, _ := pem.Decode(keyBytes)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %+v", err)
	}
	return publicKey, nil
}

// [END kms_get_asymmetric_public]

// [START kms_decrypt_rsa]

// decryptRSA will attempt to decrypt a given ciphertext with an 'RSA_DECRYPT_OAEP_2048_SHA256' private key.stored on Cloud KMS
func decryptRSA(ctx context.Context, client *cloudkms.Service, keyPath string, ciphertext []byte) ([]byte, error) {
	decryptRequest := &cloudkms.AsymmetricDecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	response, err := client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricDecrypt(keyPath, decryptRequest).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("decryption request failed: %+v", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decryted string: %+v", err)

	}
	return plaintext, nil
}

// [END kms_decrypt_rsa]

// [START kms_encrypt_rsa]

func HandlerEncryptRSA(w http.ResponseWriter, ar *http.Request){
	plaintext := ar.FormValue("plaintext")
	encodebase64 := base64.StdEncoding.EncodeToString([]byte(plaintext))
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	keyPath := "projects/styletheory-1254/locations/asia-southeast1/keyRings/styletheory-development"
	encryptedtext := encryptRSA(ctx, keyPath, []byte(encodebase64))
	fmt.Fprintf(w, encryptedtext)
}

// encryptRSA will encrypt data locally using an 'RSA_DECRYPT_OAEP_2048_SHA256' public key retrieved from Cloud KMS
func encryptRSA(ctx context.Context, keyPath string, plaintext []byte) ([]byte, error) {
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	abstractKey, err := getAsymmetricPublicKey(ctx, client, keyPath)
	if err != nil {
		return nil, err
	}

	// Perform type assertion to get the RSA key.
	rsaKey := abstractKey.(*rsa.PublicKey)

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %+v", err)
	}
	return ciphertext, nil
}

// [END kms_encrypt_rsa]

//bytes_text := decodebase64(encodebase64(encrypted))



// func decryptText(w http.ResponseWriter, r *http.Request){
// 	vars:=mux.Vars(r)
// 	bytes_text := decodebase64(vars["encrypted"])
//     original, decrypt_error := lithcrypt.Decrypt([]byte(vars["chiper"]), []byte(bytes_text))
//     if decrypt_error != nil {
//         fmt.Println("Failed to decrypt:", decrypt_error)
//         os.Exit(1)
// 	}
//     fmt.Fprintf(w, string(original))
// }

func encodebase64(b []byte) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(b))
    return string(encoded)
}

func decodebase64(s string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(s)
	return []byte(decoded)
}
