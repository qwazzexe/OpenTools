package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// Küçük gömülü common password seti (repo'ya daha büyük bir liste koyabilirsin)
var commonPasswords = map[string]struct{}{
	"123456": {}, "password": {}, "123456789": {}, "12345678": {}, "12345": {},
	"qwerty": {}, "abc123": {}, "football": {}, "111111": {}, "123123": {},
	"admin": {}, "letmein": {}, "welcome": {}, "monkey": {}, "login": {},
}

// Charset size tahmini
func charsetSize(pw string) int {
	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	size := 0
	if hasLower {
		size += 26
	}
	if hasUpper {
		size += 26
	}
	if hasDigit {
		size += 10
	}
	if hasSymbol {
		// tahmini simbol seti
		size += 32
	}
	return size
}

// Shannon entropy (basit)
func shannonEntropy(pw string) float64 {
	if len(pw) == 0 {
		return 0.0
	}
	freq := map[rune]int{}
	for _, r := range pw {
		freq[r]++
	}
	H := 0.0
	L := float64(len(pw))
	for _, v := range freq {
		p := float64(v) / L
		H -= p * math.Log2(p)
	}
	return H * L // toplam entropi tahmini
}

// Bruteforce tahmini: len * log2(charset)
func bruteforceEntropy(pw string) float64 {
	cs := float64(charsetSize(pw))
	if cs <= 1 {
		return 0.0
	}
	return float64(len(pw)) * math.Log2(cs)
}

// Tekrarlayan alt dizi kontrolü (aaaa, ababab gibi)
func hasRepeatedSequence(pw string) bool {
	L := len(pw)
	// basit yaklaşım: substring tekrarlarını kontrol et
	for sl := 1; sl <= L/2; sl++ {
		if L%sl != 0 {
			continue
		}
		sub := pw[:sl]
		rep := strings.Repeat(sub, L/sl)
		if rep == pw {
			return true
		}
	}
	// aynı karakter tekrarları (4 veya daha fazla)
	re := regexp.MustCompile(`(.)\1{3,}`)
	return re.MatchString(pw)
}

// Ardışık artan/azalan karakterler (minSeq uzunluğunda)
func hasSequentialChars(pw string, minSeq int) bool {
	if len(pw) < minSeq {
		return false
	}
	r := []rune(pw)
	// artan
	count := 1
	for i := 1; i < len(r); i++ {
		if int(r[i]) == int(r[i-1])+1 {
			count++
		} else {
			count = 1
		}
		if count >= minSeq {
			return true
		}
	}
	// azalan
	count = 1
	for i := 1; i < len(r); i++ {
		if int(r[i]) == int(r[i-1])-1 {
			count++
		} else {
			count = 1
		}
		if count >= minSeq {
			return true
		}
	}
	return false
}

func isOnlyDigitsOrLetters(pw string) bool {
	allDigits := true
	allLetters := true
	for _, r := range pw {
		if !unicode.IsDigit(r) {
			allDigits = false
		}
		if !unicode.IsLetter(r) {
			allLetters = false
		}
	}
	return allDigits || allLetters
}

// Değerlendir
type Result struct {
	Password           string
	Length             int
	ShannonEntropy     float64
	BruteforceEntropy  float64
	CharsetSize        int
	HasUpper           bool
	HasLower           bool
	HasDigit           bool
	HasSymbol          bool
	IsCommon           bool
	RepeatedSequence   bool
	Sequential         bool
	OnlyDigitsOrLetters bool
	ScoreRaw           float64
	Strength           string
}

func evaluatePassword(pw string, extraCommon map[string]struct{}) Result {
	pw = strings.TrimSpace(pw)
	res := Result{Password: pw, Length: len(pw)}
	res.ShannonEntropy = shannonEntropy(pw)
	res.BruteforceEntropy = bruteforceEntropy(pw)
	res.CharsetSize = charsetSize(pw)
	for _, r := range pw {
		if unicode.IsUpper(r) {
			res.HasUpper = true
		}
		if unicode.IsLower(r) {
			res.HasLower = true
		}
		if unicode.IsDigit(r) {
			res.HasDigit = true
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			res.HasSymbol = true
		}
	}
	_, inCommon := commonPasswords[pw]
	if extraCommon != nil {
		_, inCommon = inCommon || (func() bool { _, ok := extraCommon[pw]; return ok })()
	}
	res.IsCommon = inCommon
	res.RepeatedSequence = hasRepeatedSequence(pw)
	res.Sequential = hasSequentialChars(pw, 4)
	res.OnlyDigitsOrLetters = isOnlyDigitsOrLetters(pw)

	// Basit scoring
	score := 0.0
	score += math.Min(res.BruteforceEntropy/20.0, 5.0)
	if res.HasUpper && res.HasLower {
		score += 1.0
	}
	if res.HasDigit {
		score += 1.0
	}
	if res.HasSymbol {
		score += 1.0
	}
	if res.IsCommon {
		score -= 5.0
	}
	if res.RepeatedSequence {
		score -= 2.0
	}
	if res.Sequential {
		score -= 2.0
	}
	if res.OnlyDigitsOrLetters {
		score -= 0.5
	}
	res.ScoreRaw = math.Round(score*100) / 100
	if score < 1.5 {
		res.Strength = "WEAK"
	} else if score < 4.0 {
		res.Strength = "MODERATE"
	} else {
		res.Strength = "STRONG"
	}
	return res
}

func loadCommonFile(path string) map[string]struct{} {
	out := map[string]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[!] common file yüklenemedi: %v", err)
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t != "" {
			out[t] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[!] okuma hatası: %v", err)
	}
	return out
}

func printResult(r Result, verbose bool) {
	fmt.Println("Password audit result")
	fmt.Println("---------------------")
	fmt.Printf("Length: %d\n", r.Length)
	fmt.Printf("Strength: %s (score: %.2f)\n", r.Strength, r.ScoreRaw)
	fmt.Printf("Shannon entropy (est): %.2f bits\n", r.ShannonEntropy)
	fmt.Printf("Bruteforce entropy est: %.2f bits\n", r.BruteforceEntropy)
	fmt.Printf("Charset size estimate: %d\n", r.CharsetSize)
	if verbose {
		fmt.Printf("Has upper: %t, Has lower: %t, Has digit: %t, Has symbol: %t\n",
			r.HasUpper, r.HasLower, r.HasDigit, r.HasSymbol)
		fmt.Printf("Is common password: %t\n", r.IsCommon)
		fmt.Printf("Repeated sequence: %t, Sequential: %t, Only digits/letters: %t\n",
			r.RepeatedSequence, r.Sequential, r.OnlyDigitsOrLetters)
	}
}

func main() {
	// Flags
	passPtr := flag.String("p", "", "Password (kısa parola için). Eğer yoksa stdin veya -f kullan.")
	filePtr := flag.String("f", "", "Parola içeren dosya (her satır bir parola).")
	commonPtr := flag.String("c", "", "Ek common parola dosyası (opsiyonel).")
	verbosePtr := flag.Bool("v", false, "Detay göster")
	flag.Parse()

	var extraCommon map[string]struct{}
	if *commonPtr != "" {
		extraCommon = loadCommonFile(*commonPtr)
	}

	if *passPtr != "" {
		res := evaluatePassword(*passPtr, extraCommon)
		printResult(res, *verbosePtr)
		return
	}

	if *filePtr != "" {
		f, err := os.Open(*filePtr)
		if err != nil {
			log.Fatalf("Dosya açılamadı: %v", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			pw := scanner.Text()
			if strings.TrimSpace(pw) == "" {
				continue
			}
			res := evaluatePassword(pw, extraCommon)
			fmt.Println()
			printResult(res, *verbosePtr)
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Dosya okuma hatası: %v", err)
		}
		return
	}

	// Stdin fallback (pipe ile veya interaktif)
	info, _ := os.Stdin.Stat()
	if (info.Mode() & os.ModeCharDevice) == 0 {
		// piped input
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			pw := scanner.Text()
			if strings.TrimSpace(pw) == "" {
				continue
			}
			res := evaluatePassword(pw, extraCommon)
			printResult(res, *verbosePtr)
			fmt.Println()
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("stdin okuma hatası: %v", err)
		}
		return
	}

	// Hiçbir arg yoksa kısa help
	fmt.Println("Kullanım örnekleri:")
	fmt.Println("  password_checker -p \"MyP@ssw0rd\"")
	fmt.Println("  echo \"password123\" | password_checker")
	fmt.Println("  password_checker -f passwords.txt -v")
	fmt.Println("Flags:")
	flag.PrintDefaults()
}
