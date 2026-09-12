package wordlist

import (
	"fmt"
	"math"
	"strings"
)

func GenerateFromDomain(domain string) []string {
	var results []string
	domain = strings.ToLower(domain)
	parts := strings.Split(domain, ".")
	base := parts[0]

	results = append(results, base)
	results = append(results, base+"123")
	results = append(results, base+"1234")
	results = append(results, base+"12345")
	results = append(results, base+"!")
	results = append(results, base+"@")
	results = append(results, base+"#")
	results = append(results, base+"admin")
	results = append(results, base+"password")
	results = append(results, base+"test")
	results = append(results, base+"root")
	results = append(results, base+"dev")
	results = append(results, base+"staging")
	results = append(results, base+"prod")
	results = append(results, base+"backup")
	results = append(results, base+"api")
	results = append(results, base+"app")
	results = append(results, base+"db")
	results = append(results, base+"mail")
	results = append(results, base+"web")
	results = append(results, base+"vpn")
	results = append(results, base+"gateway")
	results = append(results, base+"proxy")
	results = append(results, base+"cdn")
	results = append(results, base+"admin123")
	results = append(results, base+"password123")
	results = append(results, base+"test123")
	results = append(results, base+"root123")
	results = append(results, base+"dev123")
	results = append(results, base+"staging123")
	results = append(results, base+"prod123")
	results = append(results, base+"backup123")
	results = append(results, base+"api123")
	results = append(results, base+"app123")
	results = append(results, base+"db123")
	results = append(results, base+"mail123")
	results = append(results, base+"web123")
	results = append(results, base+"vpn123")
	results = append(results, base+"gateway123")
	results = append(results, base+"proxy123")
	results = append(results, base+"cdn123")
	results = append(results, base+"admin!")
	results = append(results, base+"password!")
	results = append(results, base+"test!")
	results = append(results, base+"root!")
	results = append(results, base+"dev!")
	results = append(results, base+"staging!")
	results = append(results, base+"prod!")
	results = append(results, base+"backup!")
	results = append(results, base+"api!")
	results = append(results, base+"app!")
	results = append(results, base+"db!")
	results = append(results, base+"mail!")
	results = append(results, base+"web!")
	results = append(results, base+"vpn!")
	results = append(results, base+"gateway!")
	results = append(results, base+"proxy!")
	results = append(results, base+"cdn!")
	results = append(results, base+"admin@")
	results = append(results, base+"password@")
	results = append(results, base+"test@")
	results = append(results, base+"root@")
	results = append(results, base+"dev@")
	results = append(results, base+"staging@")
	results = append(results, base+"prod@")
	results = append(results, base+"backup@")
	results = append(results, base+"api@")
	results = append(results, base+"app@")
	results = append(results, base+"db@")
	results = append(results, base+"mail@")
	results = append(results, base+"web@")
	results = append(results, base+"vpn@")
	results = append(results, base+"gateway@")
	results = append(results, base+"proxy@")
	results = append(results, base+"cdn@")
	return results
}

func GenerateFromName(name string) []string {
	var results []string
	name = strings.ToLower(name)

	results = append(results, name)
	results = append(results, name+"123")
	results = append(results, name+"1234")
	results = append(results, name+"12345")
	results = append(results, name+"!")
	results = append(results, name+"@")
	results = append(results, name+"#")
	results = append(results, name+"admin")
	results = append(results, name+"password")
	results = append(results, name+"test")
	results = append(results, name+"root")
	results = append(results, name+"pass")
	results = append(results, name+"pwd")
	results = append(results, name+"1")
	results = append(results, name+"2")
	results = append(results, name+"3")
	results = append(results, name+"1!")
	results = append(results, name+"2!")
	results = append(results, name+"3!")
	results = append(results, name+"1@")
	results = append(results, name+"2@")
	results = append(results, name+"3@")
	results = append(results, name+"123!")
	results = append(results, name+"123@")
	results = append(results, name+"123#")
	results = append(results, name+"admin123")
	results = append(results, name+"password123")
	results = append(results, name+"test123")
	results = append(results, name+"root123")
	results = append(results, name+"pass123")
	results = append(results, name+"pwd123")
	results = append(results, name+"admin!")
	results = append(results, name+"password!")
	results = append(results, name+"test!")
	results = append(results, name+"root!")
	results = append(results, name+"pass!")
	results = append(results, name+"pwd!")
	results = append(results, name+"admin@")
	results = append(results, name+"password@")
	results = append(results, name+"test@")
	results = append(results, name+"root@")
	results = append(results, name+"pass@")
	results = append(results, name+"pwd@")
	return results
}

func GenerateFromEmail(email string) []string {
	var results []string
	email = strings.ToLower(email)
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return results
	}
	user := parts[0]
	domain := parts[1]
	domainParts := strings.Split(domain, ".")
	base := domainParts[0]

	results = append(results, email)
	results = append(results, user)
	results = append(results, user+"123")
	results = append(results, user+"1234")
	results = append(results, user+"12345")
	results = append(results, user+"!")
	results = append(results, user+"@")
	results = append(results, user+"#")
	results = append(results, user+"admin")
	results = append(results, user+"password")
	results = append(results, user+"test")
	results = append(results, user+"root")
	results = append(results, user+"pass")
	results = append(results, user+"pwd")
	results = append(results, user+base)
	results = append(results, user+base+"123")
	results = append(results, user+base+"!")
	results = append(results, user+base+"@")
	results = append(results, user+base+"admin")
	results = append(results, user+base+"password")
	results = append(results, user+base+"test")
	results = append(results, user+base+"root")
	results = append(results, user+base+"pass")
	results = append(results, user+base+"pwd")
	results = append(results, user+"1")
	results = append(results, user+"2")
	results = append(results, user+"3")
	results = append(results, user+"1!")
	results = append(results, user+"2!")
	results = append(results, user+"3!")
	results = append(results, user+"1@")
	results = append(results, user+"2@")
	results = append(results, user+"3@")
	results = append(results, user+"123!")
	results = append(results, user+"123@")
	results = append(results, user+"123#")
	return results
}

func GenerateMutations(wordlist []string) []string {
	var results []string
	numbers := []string{"1", "123", "1234", "12345", "123456", "0", "01", "007", "69", "420", "666", "1337"}
	specials := []string{"!", "@", "#", "$", "%", "&", "*", "+", "-", "_", ".", "?", "~"}
	years := []string{"2023", "2024", "2025", "2026", "20", "21", "22", "23", "24", "25"}

	for _, word := range wordlist {
		results = append(results, word)
		for _, num := range numbers {
			results = append(results, word+num)
			for _, sp := range specials {
				results = append(results, word+sp+num)
			}
		}
		for _, sp := range specials {
			results = append(results, word+sp)
		}
		for _, year := range years {
			results = append(results, word+year)
			for _, sp := range specials {
				results = append(results, word+sp+year)
			}
		}
	}
	return results
}

func GeneratePermutations(wordlist []string) []string {
	var results []string
	for _, word := range wordlist {
		results = append(results, word)
		runes := []rune(word)
		for i := 0; i < len(runes); i++ {
			for j := i + 1; j < len(runes); j++ {
				runes[i], runes[j] = runes[j], runes[i]
				results = append(results, string(runes))
				runes[i], runes[j] = runes[j], runes[i]
			}
		}
	}
	return results
}

func GenerateLeetSpeak(wordlist []string) []string {
	leetMap := map[rune][]rune{
		'a': {'4', '@'},
		'b': {'8'},
		'e': {'3'},
		'g': {'6', '9'},
		'i': {'1', '!'},
		'o': {'0'},
		's': {'5', '$'},
		't': {'7'},
		'l': {'1'},
		'z': {'2'},
		'h': {'#'},
	}

	var results []string
	for _, word := range wordlist {
		results = append(results, word)
		runes := []rune(strings.ToLower(word))
		for i, r := range runes {
			if replacements, ok := leetMap[r]; ok {
				for _, rep := range replacements {
					newRunes := make([]rune, len(runes))
					copy(newRunes, runes)
					newRunes[i] = rep
					results = append(results, string(newRunes))
				}
			}
		}
		for i, r := range runes {
			if replacements, ok := leetMap[r]; ok {
				for _, rep := range replacements {
					newRunes := make([]rune, len(runes))
					copy(newRunes, runes)
					newRunes[i] = rep
					for j, r2 := range runes {
						if j != i {
							if reps2, ok := leetMap[r2]; ok {
								for _, rep2 := range reps2 {
									finalRunes := make([]rune, len(newRunes))
									copy(finalRunes, newRunes)
									finalRunes[j] = rep2
									results = append(results, string(finalRunes))
								}
							}
						}
					}
				}
			}
		}
	}
	return results
}

func GenerateYearVariations(base []string) []string {
	var results []string
	years := []string{"2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026"}
	shortYears := []string{"18", "19", "20", "21", "22", "23", "24", "25", "26"}

	for _, word := range base {
		results = append(results, word)
		for _, year := range years {
			results = append(results, word+year)
			results = append(results, word+"@"+year)
			results = append(results, word+"#"+year)
			results = append(results, year+word)
			results = append(results, year+"@"+word)
		}
		for _, year := range shortYears {
			results = append(results, word+year)
			results = append(results, word+"@"+year)
			results = append(results, year+word)
		}
	}
	return results
}

func GenerateCommonPatterns() []string {
	patterns := []string{
		"password", "Password", "PASSWORD", "p@ssw0rd", "P@ssw0rd",
		"admin", "Admin", "ADMIN", "administrator", "Administrator",
		"root", "Root", "ROOT", "toor", "Toor",
		"123456", "123456789", "12345678", "12345", "1234",
		"qwerty", "Qwerty", "QWERTY", "qwertyuiop",
		"letmein", "letmein123", "LetMeIn", "Letmein1",
		"welcome", "welcome123", "Welcome", "Welcome123",
		"monkey", "dragon", "master", "login", "abc123",
		"mustang", "michael", "shadow", "sunshine", "trustno1",
		"iloveyou", "batman", "access", "superman", "hello",
		"charlie", "donald", "admin123", "passw0rd", "Passw0rd",
		"test", "test123", "guest", "guest123", "user", "user123",
		"changeme", "changeme123", "default", "password1", "password123",
		"Summer2023", "Winter2023", "Spring2023", "Fall2023",
		"Summer2024", "Winter2024", "Spring2024", "Fall2024",
		"Summer2025", "Winter2025", "Spring2025", "Fall2025",
		"Company123", "Company12345", "Secret", "Secret123",
		"temp", "temp123", "temp1234", "tmp", "tmp123",
		"test!", "test@", "test#", "admin!", "admin@",
		"root!", "root@", "root#", "pass!", "pass@",
		"qwerty!", "qwerty@", "abc!", "abc@",
	}
	return patterns
}

func GenerateKeyboardWalks() []string {
	walks := []string{
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
		"qwert", "asdfg", "zxcvb",
		"uiop", "hjkl", "bnm",
		"qazwsx", "edcrfv", "tgbyhn",
		"qaz2wsx", "edcr4rfv", "tgby6uhn",
		"!@#$%^", "123456", "abcdef",
		"zaq1xsw2", "cde3vfr4", "bgt5yhn6",
		"qweasd", "asdqwe", "qweasdzxc",
		"1qaz2wsx", "3edc4rfv", "5tgb6yhn",
		"poiuyt", "lkjhgf", "mnbvcx",
		"qazwsxedc", "rfvtgbynth", "ujmikolp",
		"qazwsx123", "edcrfv456", "tgbynth789",
		"!QAZ@WSX", "#EDC$RFV", "%TGB^YHN",
		"1q2w3e4r", "5t6y7u8i", "9o0p1q2w",
		"q1w2e3r4", "t5y6u7i8", "o9p0q1w2",
		"zaq12wsx", "edcv34rf", "tgb56yh",
		"QWERTY", "ASDFGH", "ZXCVBN",
		"qWeRtY", "aSdFgH", "zXcVbN",
	}
	return walks
}

func GeneratePhoneNumbers(country string) []string {
	var numbers []string
	switch strings.ToLower(country) {
	case "us", "usa":
		for _, prefix := range []string{"201", "202", "203", "205", "206", "207", "208", "209", "210", "212", "213", "214", "215", "216", "217", "218", "219", "224", "225", "228", "229", "231", "234", "239", "240", "248", "253", "254", "256", "260", "262", "267", "269", "270", "276", "281", "301", "302", "303", "304", "305", "307", "308", "309", "310", "312", "313", "314", "315", "316", "317", "318", "319", "320", "321", "323", "325", "330", "331", "334", "336", "337", "339", "346", "347", "351", "352", "360", "361", "364", "385", "386", "401", "402", "404", "405", "406", "407", "408", "409", "410", "412", "413", "414", "415", "417", "419", "423", "424", "425", "430", "432", "434", "435", "440", "442", "443", "469", "470", "475", "478", "479", "480", "484", "501", "502", "503", "504", "505", "507", "508", "509", "510", "512", "513", "515", "516", "517", "518", "520", "530", "531", "534", "539", "540", "541", "551", "559", "561", "562", "563", "567", "570", "571", "573", "574", "575", "580", "585", "586", "601", "602", "603", "605", "606", "607", "608", "609", "610", "612", "614", "615", "616", "617", "618", "619", "620", "623", "626", "628", "629", "630", "631", "636", "641", "646", "650", "651", "657", "660", "661", "662", "667", "669", "678", "681", "682", "701", "702", "703", "704", "706", "707", "708", "712", "713", "714", "715", "716", "717", "718", "719", "720", "724", "725", "727", "731", "732", "734", "737", "740", "743", "747", "754", "757", "760", "762", "763", "765", "769", "770", "772", "773", "774", "775", "779", "781", "785", "786", "801", "802", "803", "804", "805", "808", "810", "812", "813", "814", "815", "816", "817", "818", "828", "830", "831", "832", "843", "845", "847", "848", "850", "854", "856", "857", "858", "859", "860", "862", "863", "864", "865", "870", "872", "878", "901", "903", "904", "906", "907", "908", "909", "910", "912", "913", "914", "915", "916", "917", "918", "919", "920", "925", "928", "929", "930", "931", "936", "937", "938", "940", "941", "947", "949", "951", "952", "954", "956", "959", "970", "971", "972", "973", "975", "978", "979", "980", "984", "985", "989"} {
			for _, mid := range []string{"555", "123", "456", "789", "000", "111", "222", "333", "444", "666", "777", "888", "999", "012", "013", "014", "015", "016", "017", "018", "019", "020", "021", "022", "023", "024", "025", "026", "027", "028", "029", "030", "031", "032", "033", "034", "035", "036", "037", "038", "039", "040", "041", "042", "043", "044", "045", "046", "047", "048", "049", "050", "051", "052", "053", "054", "055", "056", "057", "058", "059", "060", "061", "062", "063", "064", "065", "066", "067", "068", "069", "070", "071", "072", "073", "074", "075", "076", "077", "078", "079", "080", "081", "082", "083", "084", "085", "086", "087", "088", "089", "090", "091", "092", "093", "094", "095", "096", "097", "098", "099"} {
				numbers = append(numbers, prefix+mid+"0000")
				numbers = append(numbers, prefix+mid+"0001")
				numbers = append(numbers, prefix+mid+"1234")
			}
		}
	case "uk":
		for _, prefix := range []string{"020", "021", "028", "029", "0113", "0114", "0115", "0116", "0117", "0118", "0121", "0131", "0141", "0151", "0161", "0191", "01204", "01205", "01206", "01207", "01208", "01209", "01223", "01224", "01225", "01226", "01227", "01228", "01229", "01234", "01235", "01236", "01237", "01238", "01239", "01242", "01243", "01244", "01245", "01246", "01248", "01249", "01252", "01253", "01254", "01255", "01256", "01257", "01258", "01259", "01260", "01261", "01262", "01263", "01264", "01267", "01268", "01269", "01270", "01271", "01273", "01274", "01275", "01276", "01277", "01278", "01279", "01280", "01282", "01283", "01284", "01285", "01286", "01287", "01288", "01289", "01290", "01291", "01292", "01293", "01294", "01295", "01296", "01297", "01298"} {
			for _, mid := range []string{"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "0123", "1234", "2345", "3456", "4567", "5678", "6789", "7890"} {
				numbers = append(numbers, prefix+mid)
			}
		}
	case "de":
		for _, prefix := range []string{"030", "040", "069", "089", "0221", "0228", "0341", "0351", "0361", "0371", "0381", "0391", "0421", "0431", "0441", "0451", "0461", "0471", "0481", "0491", "0511", "0521", "0531", "0541", "0551", "0561", "0571", "0581", "0591", "0611", "0621", "0631", "0641", "0651", "0661", "0671", "0681", "0691", "0711", "0721", "0731", "0741", "0751", "0761", "0771", "0781", "0791", "0811", "0821", "0831", "0841", "0851", "0861", "0871", "0881", "0891", "0911", "0921", "0931", "0941", "0951", "0961", "0971", "0981", "0991"} {
			for _, mid := range []string{"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "0123", "1234", "2345", "3456", "4567", "5678", "6789", "7890"} {
				numbers = append(numbers, prefix+mid)
			}
		}
	default:
		for _, prefix := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"} {
			for _, mid := range []string{"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "0123", "1234", "2345", "3456", "4567", "5678", "6789", "7890"} {
				numbers = append(numbers, prefix+mid)
			}
		}
	}
	return numbers
}

func GenerateAddresses(country string) []string {
	var addresses []string
	switch strings.ToLower(country) {
	case "us", "usa":
		streets := []string{"Main", "Oak", "Maple", "Cedar", "Elm", "Pine", "Walnut", "Spruce", "First", "Second", "Third", "Fourth", "Fifth", "Sixth", "Seventh", "Eighth", "Ninth", "Tenth", "Park", "Lake", "Hill", "River", "Forest", "Valley", "Spring", "Summer", "Winter", "Fall", "North", "South", "East", "West", "Central", "Grand", "Union", "Church", "Market", "High", "Broad", "Court"}
		suffixes := []string{"St", "Ave", "Blvd", "Dr", "Ln", "Rd", "Way", "Ct", "Pl", "Pkwy", "Hwy", "Ter", "Cir", "Loop", "Trail"}
		cities := []string{"New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "Austin", "Jacksonville", "Fort Worth", "Columbus", "Charlotte", "Indianapolis", "San Francisco", "Seattle", "Denver", "Washington", "Nashville", "Oklahoma City", "El Paso", "Boston", "Portland", "Las Vegas", "Memphis", "Louisville", "Baltimore", "Milwaukee", "Albuquerque", "Tucson", "Fresno", "Mesa", "Sacramento", "Atlanta", "Kansas City", "Colorado Springs", "Omaha", "Raleigh", "Long Beach", "Virginia Beach", "Miami", "Oakland", "Minneapolis", "Tulsa", "Tampa", "Arlington", "New Orleans"}
		states := []string{"AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"}
		zips := []string{"10001", "90001", "60601", "77001", "85001", "19101", "78201", "92101", "75201", "73301", "32099", "76101", "43085", "28201", "46201", "94101", "98101", "80201", "20001", "37201", "73101", "79901", "02101", "97201", "89101", "38101", "40201", "21201", "53201", "87101", "85701", "93701", "85201", "95814", "30301", "64101", "80901", "68101", "27601", "90801", "23451", "33101", "94601", "55401", "74101", "33601", "76001", "70112"}
		for i := 0; i < len(streets) && i < 20; i++ {
			for _, suffix := range suffixes[:5] {
				for _, num := range []string{"100", "200", "300", "400", "500", "1000", "1234", "5678"} {
					addresses = append(addresses, fmt.Sprintf("%s %s %s", num, streets[i], suffix))
				}
			}
		}
		for _, city := range cities[:10] {
			for _, state := range states[:10] {
				for _, zip := range zips[:10] {
					addresses = append(addresses, fmt.Sprintf("%s, %s %s", city, state, zip))
				}
			}
		}
	default:
		for _, num := range []string{"1", "2", "3", "4", "5", "10", "123", "456", "789", "1000"} {
			for _, street := range []string{"Main", "Oak", "Maple", "Cedar", "Elm", "Pine", "Park", "Lake", "Hill", "River"} {
				for _, suffix := range []string{"St", "Ave", "Blvd", "Dr", "Rd"} {
					addresses = append(addresses, fmt.Sprintf("%s %s %s", num, street, suffix))
				}
			}
		}
	}
	return addresses
}

func BruteForceAlphabet(length int, charset string) []string {
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyz"
	}
	runes := []rune(charset)
	var results []string
	generatePerms(runes, length, []rune{}, &results)
	return results
}

func generatePerms(charset []rune, length int, current []rune, results *[]string) {
	if length == 0 {
		*results = append(*results, string(current))
		return
	}
	for _, r := range charset {
		generatePerms(charset, length-1, append(current, r), results)
	}
}

func CombineWordlists(lists ...[]string) []string {
	var combined []string
	seen := make(map[string]bool)
	for _, list := range lists {
		for _, word := range list {
			if !seen[word] {
				seen[word] = true
				combined = append(combined, word)
			}
		}
	}
	return combined
}

func FilterByLength(wordlist []string, min, max int) []string {
	var filtered []string
	for _, word := range wordlist {
		l := len(word)
		if l >= min && l <= max {
			filtered = append(filtered, word)
		}
	}
	return filtered
}

func FilterByComplexity(wordlist []string, minComplexity int) []string {
	var filtered []string
	for _, word := range wordlist {
		if calculateComplexity(word) >= minComplexity {
			filtered = append(filtered, word)
		}
	}
	return filtered
}

func CalculateEntropy(wordlist []string) float64 {
	if len(wordlist) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	total := 0
	for _, word := range wordlist {
		for _, r := range word {
			freq[r]++
			total++
		}
	}
	if total == 0 {
		return 0
	}
	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func calculateComplexity(s string) int {
	complexity := 0
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if hasUpper {
		complexity++
	}
	if hasLower {
		complexity++
	}
	if hasDigit {
		complexity++
	}
	if hasSpecial {
		complexity++
	}
	if len(s) >= 8 {
		complexity++
	}
	if len(s) >= 12 {
		complexity++
	}
	return complexity
}
