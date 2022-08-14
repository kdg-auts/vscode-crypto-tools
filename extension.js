const vscode = require('vscode');
const system = require('child_process').exec;
const caesar = require('./scripts/Caesar');
const vigenere = require('./scripts/Vigenere');
const morse = require('xmorse');
const basic = require('./scripts/Basic');
const manip = require('./scripts/textManipulation');
const crypto = require('crypto');
const fs = require('fs')
const fence = require('./scripts/Fence')

/**
 * Triggered when the plugin is activated, the total entry of all codes
 * @param {*} context plugin context
 */

//format
String.prototype.format = function () {
	var args = arguments;
	return this.replace(/\{(\d+)\}/gm, (ms, p1) => {
		return typeof (args[p1]) == 'undefined' ? ms : args[p1]
	});
}

//Display information and update text
function print(text) {
	outputChannel.show();
	outputChannel.appendLine(text);
}

function showUpdate(alg, before, after, update) {
	if (after) {
		//output
		print("------------------------------------")
		print("  ◆   " + alg + ":");
		print('[ ⇐ ] ' + before);
		print('[ ⇒ ] ' + after);
		//update
		if (update) {
			editor.edit(editBuilder => {
				editBuilder.replace(selection, after);
			});
			print('[ ✔ ] Text has been updated automatically, press Ctrl + Z to undo');
		}
		print("------------------------------------");
	} else {
		vscode.window.showErrorMessage("Conversion failed! Please check the text type or check the log!")
	}
}


//crack hash
function crackHash(text) {
	vscode.window.showInformationMessage("Please ensure that the network and Python environment are normal and are being cracked...");
	system('python {0}/scripts/HashBuster.py -s {1}'.format(__dirname, text), (err, stdout) => {
		if (stdout.indexOf("[-]") == -1) {
			let hashtype = stdout.split('\n')[0].split('[!]')[1].trim()
			let plaintext = stdout.split('\n')[1].trim()
			vscode.window.showInformationMessage(hashtype);
			showUpdate("hashBuster", text, plaintext, true);
		} else {
			let result = stdout.split('[-]');
			let errorMessage = result[1].trim();
			vscode.window.showErrorMessage(errorMessage);
			if (result[0]) {
				let hashtype = result[0].split('[!]')[1].trim();
				vscode.window.showInformationMessage(hashtype);
			}
		}
		if (err) {
			print('[ ✘ ] ' + err);
		}
	})
}

function crackHashInFile() {
	let file = vscode.window.activeTextEditor.document.fileName;
	vscode.window.showInformationMessage("Please ensure that the network and Python environment are normal and are being cracked...");
	system('python {0}/scripts/HashBuster.py -f {1}'.format(__dirname, file), (err, stdout) => {
		print("------------------------------------");
		print(stdout)
		print("------------------------------------");
		if (err) {
			print('[ ✘ ] ' + err);
		}
	})
}

//Caesar
async function Caesar(text) {
	result = caesar.caesar(text);
	console.log(result);
	let choise = await vscode.window.showQuickPick(result, {
		placeHolder: 'Choose one of the results to replace'
	});
	if (choise) {
		vscode.window.showInformationMessage("selected displacement " + result.indexOf(choise) + " bit result");
		showUpdate("Caesar", text, choise, true);
	}
}
//displacement
async function Shift(text) {
	let value = await vscode.window.showInputBox({
		prompt: 'Enter the maximum number of shift bits N and the direction L or R, separated by commas',
		value: "50,l"
	});
	if (value) {
		let n = value.split(',')[0];
		let d = value.split(',')[1];
		result = caesar.shift(text, n, d);
		console.log(result);
		let choise = await vscode.window.showQuickPick(result, {
			placeHolder: 'Choose one of the results to replace'
		});
		if (choise) {
			vscode.window.showInformationMessage("selected displacement " + result.indexOf(choise) + " bit result");
			showUpdate("Shift", text, choise, true);
		}
	}
}
//fence
async function Fence(text, alg) {
	let result = []
	if (alg.includes("Encode")) {
		for (var i = 2; i < text.length; i++) {
			result.push(fence.encrypt(text, i))
		}
	} else {
		for (var i = 2; i < text.length; i++) {
			result.push(fence.decrypt(text, i))
		}
	}
	console.log(result);
	let choise = await vscode.window.showQuickPick(result, {
		placeHolder: 'Choose one of the results to replace'
	});
	if (choise) {
		vscode.window.showInformationMessage("The number of columns selected is " + (result.indexOf(choise) + 2) + " result");
		showUpdate("Shift", text, choise, true);
	}
}

//Vigenere
async function Vigenere(text, alg) {
	let key = await vscode.window.showInputBox({
		placeHolder: 'enter key'
	});
	if (key) {
		if (alg.includes("Encode")) {
			var result = vigenere.Vigenere(text, key, true);
		} else {
			var result = vigenere.Vigenere(text, key, false);
		}
		showUpdate(alg, text, result, true);
	}
}


async function vigenereAutoDecode(text) {
	let minlen = 1; //Guess the length of the key from 1
	while (true) {
		let guessKey = new Promise((resolve) => {
			let result = vigenere.deVigenereAuto(text, false, minlen, 100); //The length of the default key is unknown
			resolve(result);
		});
		result = await guessKey;
		showUpdate("vigenereAutoDecode", text, result[0], false);
		print("The most likely keys are:" + result[1]);
		minlen = result[2] + 1; //If the guess is not correct, continue to guess from the guessed key length + 1
		let choise = await vscode.window.showInformationMessage("Please confirm in the output log whether the key and plaintext are guessed correctly？", "Yes", "No");
		if (choise != "No") {
			showUpdate("vigenereAutoDecode", text, result[0], true);
			break;
		}
	}
}

//Symmetric encryption
async function symmetricCryption(text, alg) {
	let algorithm = await vscode.window.showQuickPick(crypto.getCiphers(), {
		placeHolder: "Please select the symmetric encryption algorithm to use"
	})
	if (algorithm) {
		let value = await vscode.window.showInputBox({
			placeHolder: 'Please enter the secret key and initial vector, separated by commas, optional',
		});
		let key = value.split(',')[0] || "";
		let iv = value.split(',')[1] || "";
		print("Key: " + key + " IV: " + iv)
		try {
			if (alg.includes("Encryption")) {
				if (iv) {
					var cipher = crypto.createCipheriv(algorithm, key, iv);
				} else {
					var cipher = crypto.createCipher(algorithm, key);
				}
				var result = cipher.update(text, 'utf8', 'base64');
				result += cipher.final('base64');
			} else {
				if (iv) {
					var decipher = crypto.createDecipheriv(algorithm, key);
				} else {
					var decipher = crypto.createDecipher(algorithm, key);
				}
				var result = decipher.update(text, 'base64', 'utf8');
				result += decipher.final('utf8');
			}
		} catch (err) {
			print('[ ✘ ] ' + err)
		}
		showUpdate(alg + " - " + algorithm, text, result, true);
	}
}

//RSA encryption
function checkKey(keyfile, key) {
	let pri = [crypto.privateEncrypt, crypto.privateDecrypt];
	let pub = [crypto.publicEncrypt, crypto.publicDecrypt]
	if (key.includes("PRIVATE")) {
		print("Private key file selected: " + keyfile)
		return pri
	} else if (key.includes("PUBLIC")) {
		print("Public key file selected: " + keyfile)
		return pub
	} else {
		print("[ ✘ ] The key format seems to be wrong");
		print("The private key begins and ends with:");
		print("-----BEGIN RSA PRIVATE KEY-----");
		print("-----END RSA PRIVATE KEY-----");
		print("The public key begins and ends with:");
		print("-----BEGIN PUBLIC KEY-----");
		print("-----END PUBLIC KEY-----")
	}
}

async function rsaCryption(text, alg) {
	try {
		let file = await vscode.window.showOpenDialog({
			openLabel: 'Select key'
		});
		if (file) {
			let keyfile = file[0].fsPath;
			let key = fs.readFileSync(keyfile).toString('utf-8')
			if (alg.includes("Encryption")) {
				crypt = checkKey(keyfile, key)[0];
				var result = crypt(key, new Buffer(text)).toString('base64');
			} else {
				crypt = checkKey(keyfile, key)[1];
				var result = crypt(key, new Buffer(text, 'base64')).toString("utf8");
			}
			showUpdate(alg, text, result, true);
		}
	} catch (err) {
		print(err)
	}
}

//Morse
async function Morse(text, alg) {
	let value = await vscode.window.showInputBox({
		value: "{ space: '/', long: '-', short: '.' }",
		prompt: "Please enter the corresponding spacer, dash, dot symbol"
	});
	if (value) {
		let option = eval('(' + value + ')');
		if (alg.includes("Encode")) {
			var result = morse.encode(text, option);
		} else {
			var result = morse.decode(text, option);
		}
		showUpdate(alg, text, result, true)
	};
}

//hex calculator
async function calculator(text) {
	let value = await vscode.window.showInputBox({
		placeHolder: 'Enter the formula to be calculated, non-decimal numbers start with 0x, 0b, 0o',
		value:text
	});
	if (value) {
		try {
			let result = eval(value)
			let dec = parseFloat(result);
			let hex = "0x" + dec.toString(16);
			let oct = "0o" + dec.toString(8);
			let bin = "0b" + dec.toString(2);
			let str = /^[\x20-\x7e]+$/.test(basic.number2string(dec)) && basic.number2string(dec)
			log = `dec: {0}
			hex: {1}
			bin: {2}
			oct: {3}`.format(dec, hex, bin, oct);
			if (str) {
				log += '\n			str: "{0}"'.format(str)
			}
			showUpdate("hexadecimalConverter", value, log, false);
		}
		catch (err) {
			vscode.window.showErrorMessage("Enter a non-formula, it will be converted to hexadecimal first and then calculated")
			let hex = '0x' + basic.string2hex(value);
			calculator(hex);
			}
	}
}

//Handle text/x-code-output compatibility issues
//Get the highlighted syntax of the output channel
function getPatterns(file) {
	let content = fs.readFileSync(file, "utf-8");
	let patterns = /<key>patterns<\/key>[\s|\S]*?<array>([\s|\S]*?)<\/array>/.exec(content)[1];
	return patterns
}

//Remove "text/x-code-output" in the related plugin JSON file to avoid conflicts
function rmOutput(file) {
	let content = fs.readFileSync(file, "utf-8");
	let New = content.replace("text/x-code-output", "text/bak-x-code-output");
	fs.writeFileSync(file, New);
}

//Get the file that defines the output channel syntax and integrate the syntax
function getLang() {
	let lang = '';
	const extension = vscode.extensions.all
	for (let e of extension) {
		try {
			let mimetypes = e.packageJSON.contributes.languages[0].mimetypes;
			if (mimetypes.includes("text/x-code-output")) {
				let id = e.id;
				if (id != "fofolee.crypto-tools") {
					let extensionPath = e.extensionPath;
					let grammarsPath = e.packageJSON.contributes.grammars[0].path.substr(1);
					rmOutput(manip.convPath(extensionPath + "/package.json"));
					print("Found conflicting plugins that define output syntax:\n" + extensionPath);
					file = manip.convPath(extensionPath + grammarsPath);
					console.log(file);
					lang += '        <!-- ' + id + ' start -->' + getPatterns(file) + '<!-- ' + id + ' end -->\n';
				}
			}
		} catch (err) {
		}
	}
	return lang
}


outputChannel = vscode.window.createOutputChannel('crypto');

exports.activate = context => {
	// register command
	context.subscriptions.push(vscode.commands.registerCommand('crypto.EncodeDecode', async () => {
		editor = vscode.window.activeTextEditor;
		selection = editor.selection;
		let text = editor.document.getText(selection).trim();
		let algorithm = await vscode.window.showQuickPick([{
				label: "ROT13",
				detail: "ROT13 encryption",
				target: basic.rot13
			},
			{
				label: "Base64/32/16 Decode",
				detail: "Automatic base64/32/16 decryption",
				target: basic.baseDecode
			},
			{
				label: "Base64 Encode",
				detail: "base64 encryption",
				target: basic.base64Encode
			},
			{
				label: "Base32 Encode",
				detail: "base32 encryption",
				target: basic.base32Encode
			},
			{
				label: "Base16 Encode",
				detail: "base16 encryption",
				target: basic.base16Encode
			},
			{
				label: "MD5",
				detail: "MD5 hash algorithm",
				target: basic.md5Hash
			},
			{
				label: "SHA512",
				detail: "SHA512 hash algorithm",
				target: basic.sha512Hash
			},
			{
				label: "Url Decode",
				detail: "url decode",
				target: basic.urlDecode
			},
			{
				label: "Url Encode",
				detail: "url encode",
				target: basic.urlEncode
			},
			{
				label: "Html Entities",
				detail: "html encode",
				target: basic.htmlEncode
			},
			{
				label: "Html Entity Decode",
				detail: "html decode",
				target: basic.htmlDecode
			},
			{
				label: "Quote-Printable Decode",
				detail: "Quote-Printable decode",
				target: basic.quopriDecode
			},
			{
				label: "Quote-Printable Encode",
				detail: "Quote-Printable encode",
				target: basic.quopriEncode
			},
			{
				label: "Bubble Babble Decode",
				detail: "Bubble Babble decode",
				target: basic.bubbleDecode
			},
			{
				label: "Bubble Babble Encode",
				detail: "Bubble Babble encode",
				target: basic.bubbleEncode
			},
			{
				label: "Brainfuck Decode",
				detail: "Brainfuck decode",
				target: basic.brainfuckDecode
			},
			{
				label: "Number To String",
				detail: "Integer to character",
				target: basic.number2string
			},
			{
				label: "String To Number",
				detail: "Character to integer",
				target: basic.string2number
			},
			{
				label: "String To Hex",
				detail: "Character to Hexadecimal",
				target: basic.string2hex
			},
			{
				label: "Hex To String",
				detail: "Hexadecimal to Character",
				target: basic.hex2string
			},
			{
				label: "String To Bin",
				detail: "Character to Binary",
				target: basic.string2bin
			},
			{
				label: "Bin To String",
				detail: "Binary to Character",
				target: basic.bin2string
			}
		], {
			placeHolder: 'choose an algorithm'
		});
		if (algorithm) {
			let result = algorithm.target(text);
			showUpdate(algorithm.label, text, result, true);
		}
	}));

	context.subscriptions.push(vscode.commands.registerCommand('crypto.EncryptDecrypt', async () => {
		editor = vscode.window.activeTextEditor;
		selection = editor.selection;
		let text = editor.document.getText(selection).trim();
		let algorithm = await vscode.window.showQuickPick([{
				label: "Crack Hash",
				detail: "Cracking the selected hash",
				target: crackHash
			},
			{
				label: "Crack Hashes In File",
				detail: "Cracking all hashes in the current file",
				target: crackHashInFile
			},
			{
				label: "Symmetric Decryption",
				detail: "Symmetric cipher decryption algorithm, the ciphertext format is Base64",
				target: symmetricCryption
			},
			{
				label: "Symmetric Encryption",
				detail: "Symmetric cipher encryption algorithm, the ciphertext format is Base64",
				target: symmetricCryption
			},
			{
				label: "RSA Decryption",
				detail: "RSA decryption using public or private key file",
				target: rsaCryption
			},
			{
				label: "RSA Encryption",
				detail: "RSA encryption using public or private key files",
				target: rsaCryption
			},
			{
				label: "Caesar Cipher",
				detail: "Caesar Cipher",
				target: Caesar
			},
			{
				label: "Character Offset",
				detail: "Character Offset",
				target: Shift
			},
			{
				label: "Fence Decode",
				detail: "Fence Decode",
				target: Fence
			},
			{
				label: "Fence Encode",
				detail: "Fence Encode",
				target: Fence
			},
			{
				label: "Vigenere Encode",
				detail: "Vigenere Encode",
				target: Vigenere
			},
			{
				label: "Vigenere Decode",
				detail: "Vigenere Decode",
				target: Vigenere
			},
			{
				label: "Vigenere Decode with No Key",
				detail: "Vigenere Decode with No Key",
				target: vigenereAutoDecode
			},
			{
				label: "Morse Encode",
				detail: "Morse Encode",
				target: Morse
			},
			{
				label: "Morse Decode",
				detail: "Morse Decode",
				target: Morse
			}
		], {
			placeHolder: 'choose an algorithm'
		});
		if (algorithm) {
			algorithm.target(text, algorithm.label);
		}

	}));

	context.subscriptions.push(vscode.commands.registerCommand('crypto.textManipulation', async () => {
		editor = vscode.window.activeTextEditor;
		selection = editor.selection;
		let text = editor.document.getText(selection).trim();
		let algorithm = await vscode.window.showQuickPick([{
				label: "Reverse String",
				detail: "Reverse String",
				target: manip.reverseString
			},
			{
				label: "Upper Case",
				detail: "To Upper Case",
				target: manip.upperString
			},
			{
				label: "Lower Case",
				detail: "To Lower Case",
				target: manip.lowerString
			},
			{
				label: "Strip String",
				detail: "Remove left and right spaces and newlines",
				target: manip.stripString
			},
			{
				label: "Space To None",
				detail: "remove all spaces",
				target: manip.space2None
			},
			{
				label: "Space To Line",
				detail: "space conversion to new line",
				target: manip.space2Line
			},
			{
				label: "Convert Path",
				detail: "\\ and / interchange",
				target: manip.convPath
			},
			{
				label: "Title Case",
				detail: "Capitalize all words",
				target: manip.titleCase
			},
			{
				label: "String Lenght",
				detail: "Get text length",
				target: manip.stringLen
			},
			{
				label: "Add Quot By Comma",
				detail: "Put double quotes around each comma-separated word",
				target: manip.addQuotByComma
			},
			{
				label: "Add Quot By Space",
				detail: "Put double quotes around each space-separated word",
				target: manip.addQuotBySpace
			}
		], {
			placeHolder: 'Choose a conversion type'
		});
		if (algorithm) {
			let result = algorithm.target(text);
			if (algorithm.label != "String Lenght") {
				showUpdate(algorithm.label, text, result, true);
			} else {
				showUpdate(algorithm.label, text, result, false);
				vscode.window.showInformationMessage("The length is: " + result);
			}
		}

	}));

	context.subscriptions.push(vscode.commands.registerCommand('crypto.hexadecimalCalculator', () => {
		calculator("");

	}));

	context.subscriptions.push(vscode.commands.registerCommand('crypto.outputColorPatch', async () => {
		let choise = await vscode.window.showInformationMessage("If the output of this plugin is not highlighted, or the output of other plugins is not highlighted after installing this plugin, it is because of conflicts with the output syntax of some other plugins. Do you try to fix these conflicts automatically? ", "Yes", "No")
		if (choise == "Yes") {
			print("trying to find the problem...");
			let langFile = __dirname + "/syntaxes/crypto-tools-output.tmLanguage";
			let file = fs.readFileSync(langFile, "utf-8");
			let lang = getLang();
			let New = file.replace("        </array>", lang + "        </array>");
			console.log(New);
			fs.writeFileSync(langFile, New);
			if (lang) {
				print("The grammar file has been integrated, please restart the editor!")
			} else {
				print("No conflicting files found!")
			}
		}

	}));

};
