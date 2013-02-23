package com.untamedears.DynCap;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.logging.Logger;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bukkit.Bukkit;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerKickEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

// START DEBUG ONLY IMPORTS
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
// END DEBUG ONLY IMPORTS

public class DynCapPlugin extends JavaPlugin implements Listener {
	public static final int kTicksPerSec = 20;
	public static final int kMaxFailures = 2;
	// Need to install the "Java Cryptography Extension (JCE)
	// Unlimited Strength Jurisdiction Policy Files" to support
	// 256-bit keys, aka. 32 bytes.
	public static final int kAesKeyLength = 32; // Can be 16 or 32
	public static final int kAesIVLength = 16;

	public static DynCapPlugin plugin_ = null;

	public static DynCapPlugin get() {
		return plugin_;
	}

	// START DEBUG: This section is for debugging only when there is no valid SSL
	// certificate for the site
	private static class DefaultTrustManager implements X509TrustManager {
		@Override
		public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
		@Override
		public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}
	static {
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session)
			{
				// ip address of the service URL
				if (hostname.equals("67.205.32.32"))
					return true;
				return false;
			}
		});
		SSLContext ctx;
		try {
			ctx = SSLContext.getInstance("TLS");
			ctx.init(new KeyManager[0], new TrustManager[] {new DefaultTrustManager()}, new SecureRandom());
		} catch (Exception ex) {
			System.out.println(generateExceptionReport(ex));
			throw new Error(ex);
		}
		SSLContext.setDefault(ctx);
	}
	// END DEBUG

	public static String generateExceptionReport(Throwable ex) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		pw.println("Internal error!");
		pw.println("Include the following into your bug report:");
		pw.println("======= SNIP HERE =======");
		pw.println(ex.toString());
		ex.printStackTrace(pw);
		pw.println("======= SNIP HERE =======");
		String report = sw.toString();
		try {
			pw.close();
			sw.close();
		} catch(IOException e) {}
		return report;
	}

	public static Cipher makeCipher(
			String spec, Key cryptoKey, AlgorithmParameterSpec cryptoIv) {
		if (spec == null || cryptoKey == null || cryptoIv == null) {
			return null;
		}
		try {
			Cipher cipher = Cipher.getInstance(spec);
			cipher.init(Cipher.DECRYPT_MODE, cryptoKey, cryptoIv);
			return cipher;
		} catch (Exception ex) {
			DynCapPlugin.get().error(generateExceptionReport(ex));
			throw new Error(ex);
		}
	}

	public static Key makeKey(String secret) {
		if (secret == null) {
			return null;
		}
		try {
			byte[] secretBytes = secret.getBytes("UTF-8");
			if (secretBytes.length < kAesKeyLength) {
				throw new Error(String.format(
					"Encryption secret must be %d bytes", kAesKeyLength));
			}
			byte[] keyBytes = new byte[kAesKeyLength];
			System.arraycopy(secretBytes, 0, keyBytes, 0, kAesKeyLength);
			return new SecretKeySpec(keyBytes, "AES");
		} catch (Exception ex) {
			DynCapPlugin.get().error(generateExceptionReport(ex));
			throw new Error(ex);
		}
	}

	public static AlgorithmParameterSpec makeIv(byte[] rawBytes) {
		if (rawBytes == null) {
			return null;
		}
		try {
			// IVs are always 128-bit in Java
			if (rawBytes.length < kAesIVLength) {
				throw new Error(String.format(
					"Encryption IV must be %d bytes", kAesIVLength));
			}
			byte[] ivBytes = new byte[kAesIVLength];
			System.arraycopy(rawBytes, 0, ivBytes, 0, kAesIVLength);
			return new IvParameterSpec(ivBytes);
		} catch (Exception ex) {
			DynCapPlugin.get().error(generateExceptionReport(ex));
			throw new Error(ex);
		}
	}

	private DynCapCommands commands;
	private int dynamicPlayerCap = 1000;
	private Logger log;
	private boolean bukkitWhiteListEnabled = false;
	private boolean dyncapWhiteListEnabled = false;
	private Set<String> dyncapPlayers = new HashSet<String>();
	private String playersWLFile;
	private String playersWLUrl;
	private Integer dyncapPlayersReloadSec;
	private String dyncapPlayersCipherAlgorithm;
	private Key dyncapPlayersCipherSecret;
	private BukkitTask wlReloadTask;
	private int dyncapPlayersReloadFailures = 0;
	private long dyncapWLFileLastModified = 0;
	private long dyncapWLUrlLastModified = 0;

	public void error(String msg) {
		log.severe(msg);
	}

	public void warn(String msg) {
		log.warning(msg);
	}

	public void info(String msg) {
		log.info(msg);
	}

	public void onEnable() {
		plugin_ = this;
		log = this.getLogger();
		commands = new DynCapCommands(this, log);
		
		Bukkit.getPluginManager().registerEvents(this, this);
		for (String command : getDescription().getCommands().keySet()) {
			getCommand(command).setExecutor(commands);
		}

		this.reloadConfig();
		FileConfiguration config = this.getConfig();
		config.options().copyDefaults(true);
		dynamicPlayerCap = config.getInt("initial-cap", 1000);
		playersWLFile = config.getString("dyncap-whitelist-file");
		playersWLUrl = config.getString("dyncap-whitelist-url");
		if (playersWLFile != null || playersWLUrl != null) {
			dyncapWhiteListEnabled = true;
			info("DynCap white-list enabled");
			dyncapPlayersReloadSec = config.getInt("dyncap-whitelist-interval");
			dyncapPlayersCipherAlgorithm = config.getString(
				"dyncap-whitelist-crypto", "AES/CBC/PKCS5Padding");
			dyncapPlayersCipherSecret = makeKey(
				config.getString("dyncap-whitelist-secret"));
			info("Encryption enabled");
		}

		scheduleDyncapWhitelistReload();

		// Give the console permission
		ConsoleCommandSender console = getServer().getConsoleSender();
		console.addAttachment(this, "dyncap.console", true);
	}

	public void onDisable() {}

	@EventHandler(priority=EventPriority.LOWEST, ignoreCancelled=false)
	public void onAsyncPlayerPreLoginEvent(AsyncPlayerPreLoginEvent event) {
		if (bukkitWhiteListEnabled &&
			event.getLoginResult() == AsyncPlayerPreLoginEvent.Result.ALLOWED)
		{
			return;
		} else if (dyncapWhiteListEnabled &&
			!dyncapPlayers.contains(event.getName().toLowerCase()))
		{
			event.disallow(
				AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
				"Not registered.");
		} else if (isServerFull()) {
			event.disallow(
				AsyncPlayerPreLoginEvent.Result.KICK_FULL,
				"Server full.");
		} else {
			return;
		}
	}

	@EventHandler(priority=EventPriority.MONITOR)
	public void onPlayerJoinEvent(PlayerJoinEvent event) {
		updatePlayerCap(getPlayerCount());
	}

	@EventHandler(priority=EventPriority.MONITOR)
	public void onPlayerQuitEvent(PlayerQuitEvent event) {
		updatePlayerCap(getPlayerCount() - 1);
	}

	@EventHandler(priority=EventPriority.MONITOR)
	public void onPlayerKickEvent(PlayerKickEvent event) {
		updatePlayerCap(getPlayerCount() - 1);
	}

	public void setPlayerCap(int cap) {
		dynamicPlayerCap = cap;
		updatePlayerCap(getPlayerCount());
	}

	public int getPlayerCap() {
		return dynamicPlayerCap;
	}

	private void updatePlayerCap(int playerCount) {
		if (playerCount >= dynamicPlayerCap) {
			setWhitelist(true, playerCount);
		} else if (playerCount < dynamicPlayerCap) {
			setWhitelist(false, playerCount);
		}
	}

	private void setWhitelist(boolean enabled, int playerCount) {
		if ((enabled && !bukkitWhiteListEnabled) ||
			(!enabled && bukkitWhiteListEnabled))
		{
			Integer cap = getPlayerCap();
			String state_message = "disabled";
			if (enabled) {
				state_message = "enabled";
			}
			info(String.format(
				"%d/%d players online dynamic cap %s.",
				playerCount, cap, state_message));
		}
		bukkitWhiteListEnabled = enabled;
		Bukkit.setWhitelist(enabled);
	}

	public int getPlayerCount() {
		return this.getServer().getOnlinePlayers().length;
	}

	public boolean isServerFull() {
		return getPlayerCount() >= getPlayerCap();
	}

	private void scheduleDyncapWhitelistReload() {
		if (!dyncapWhiteListEnabled) { return; }
		wlReloadTask = this.getServer().getScheduler().runTaskTimerAsynchronously(
			this,
			new Runnable() {
				@Override
				public void run() {
					DynCapPlugin.get().ReloadDyncapWhitelist();
				}
			},
			1L,
			dyncapPlayersReloadSec * kTicksPerSec);
	}

	public void ReloadDyncapWhitelist() {
		if (!ReloadDWLUri() && !ReloadDWLFile()) {
			ReloadDyncapWhitelistFailure();
		} else {
			dyncapPlayersReloadFailures = 0;
			info(String.format(
				"Loaded %d players into DynCap white-list",
				dyncapPlayers.size()));
		}
	}

	private boolean ReloadDWLFile() {
		if (playersWLFile == null) { return false; }
		BufferedReader br = null;
		try {
			File f = new File(playersWLFile);
			if (!f.exists()) {
				return false;
			}
			long lastModified = f.lastModified();
			if (dyncapWLFileLastModified == lastModified) {
				return true;
			}
			dyncapWLFileLastModified = lastModified;
			br = getDWLReader(new FileInputStream(f), null);
			dyncapPlayers = LoadDWLFromReader(br);
			return true;
		} catch (Exception ex) {
			error("Exception occurred while loading the DynCap white-list via File");
			error(generateExceptionReport(ex));
		} finally {
			try {
				if (br != null) { br.close(); }
			} catch (Exception ex) {
			}
		}
		return false;
	}

	private boolean ReloadDWLUri() {
		if (playersWLUrl == null) { return false; }
		URL url = null;
		try {
			url = new URL(playersWLUrl);
		} catch (Exception ex) {
			throw new Error(String.format("Invalid URL (%s): %s", playersWLUrl, ex.toString()));
		}
		String protocol = url.getProtocol();
		if (!protocol.equals("http") && !protocol.equals("https") &&
				!protocol.equals("file")) {
			throw new Error("Invalid protocol: " + protocol);
		}
		BufferedReader br = null;
		try {
			URLConnection connection = url.openConnection();
			connection.setUseCaches(true);
			if (dyncapWLUrlLastModified != 0) {
				connection.setIfModifiedSince(dyncapWLUrlLastModified);
			}
			connection.connect();
			byte[] rawData = ReadAllStream(connection.getInputStream());
			byte[] ivBytes = null;
			String b64_encoded = new String(rawData, "UTF-8");
			if (b64_encoded.charAt(24) == '!') {
				String b64_header = b64_encoded.substring(0, 24);
				ivBytes = DatatypeConverter.parseBase64Binary(b64_header);
				b64_encoded = b64_encoded.substring(25);
			}
			rawData = DatatypeConverter.parseBase64Binary(b64_encoded);
			br = getDWLReader(new ByteArrayInputStream(rawData), ivBytes);
			dyncapPlayers = LoadDWLFromReader(br);
			dyncapWLUrlLastModified = connection.getLastModified();
			return true;
		} catch (Exception ex) {
			error("Exception occurred while loading the DynCap white-list via URI");
			error(generateExceptionReport(ex));
			throw new Error(ex);
		} finally {
			try {
				if (br != null) { br.close(); }
			} catch (IOException ex) {
			}
		}
	}

	private byte[] ReadAllStream(InputStream in) {
		try {
			byte[] buffer = new byte[65535];
			byte[] blob = new byte[0];
			while (true) {
				int read = in.read(buffer);
				if (read <= 0) {
					break;
				}
				byte[] tmpBlob = new byte[blob.length + read];
				System.arraycopy(blob, 0, tmpBlob, 0, blob.length);
				System.arraycopy(buffer, 0, tmpBlob, blob.length, read);
				blob = tmpBlob;
			}
			return blob;
		} catch (IOException ex) {
			error("Exception occurred while reading the input stream");
			error(generateExceptionReport(ex));
			throw new Error(ex);
		} finally {
			try {
				in.close();
			} catch (IOException ex) {
			}
		}
	}

	private BufferedReader getDWLReader(InputStream in, byte[] ivBytes) {
		try {
			if (dyncapPlayersCipherAlgorithm != null && ivBytes != null) {
				// In the format: AAAAAAAAAAAAAAAAAAAAAA==!
				// 25 raw bytes for 16 byte IV
				Cipher cipher = makeCipher(
					dyncapPlayersCipherAlgorithm,
					dyncapPlayersCipherSecret,
					makeIv(ivBytes));
				in = new CipherInputStream(in, cipher);
			}
			return new BufferedReader(new InputStreamReader(in, "UTF-8"));
		} catch (Exception ex) {
			error(generateExceptionReport(ex));
			throw new Error(ex);
		}
	}

	private Set<String> LoadDWLFromReader(BufferedReader br) throws IOException {
		Set<String> new_players = new HashSet<String>();
		while (br.ready()) {
			String line = br.readLine().trim().toLowerCase();
			if (line.length() <= 0) { continue; }
			if (line.charAt(0) == '#') { continue; }
			info(line); //XXX
			new_players.add(line);
		}
		return new_players;
	}

	private boolean ReloadDyncapWhitelistFailure() {
		++dyncapPlayersReloadFailures;
		if (dyncapPlayersReloadFailures >= kMaxFailures) {
			// TODO: Ponder failure scenarios. Should it lock down the server
			//  until a server restart?
			log.severe("DynCap WhiteList max failures reached");
			wlReloadTask.cancel();
			dyncapWhiteListEnabled = false;
			playersWLFile = null;
			playersWLUrl = null;
			return true;
		}
		return false;
	}
}
