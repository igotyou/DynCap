package com.untamedears.DynCap;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.Reader;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Logger;
import java.util.Set;
//import javax.crypto.Cipher;
//import javax.crypto.CipherInputStream;
//import javax.crypto.spec.IvParameterSpec;
//import sun.misc.BASE64Decoder;

import org.bukkit.Bukkit;
import org.bukkit.World;
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

public class DynCapPlugin extends JavaPlugin implements Listener {
    public static final int kTicksPerSec = 20;
    public static final int kMaxFailures = 2;

    public static DynCapPlugin plugin_ = null;

    public static DynCapPlugin getPlugin() {
        return plugin_;
    }

	private DynCapCommands commands;
	private int dynamicPlayerCap = 1000;
	private Logger log;
	private boolean bukkitWhiteListEnabled = false;
    private boolean dyncapWhiteListEnabled = false;
    private Set<String> dyncapPlayers = new HashSet<String>();
    private String dyncapPlayersFile;
    private Integer dyncapPlayersReloadSec;
    private String dyncapPlayersCryptoAlgorithm;
    private String dyncapPlayersCryptoPassword;
    private byte[] dyncapPlayersCryptoIv;
    private BukkitTask wlReloadTask;
    private int dyncapPlayersReloadFailures = 0;
    private long dyncapWLFileLastModified = 0;
    private long dyncapWLUrlLastModified = 0;

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
        dyncapPlayersFile = config.getString("dyncap-whitelist-file");
        if (dyncapPlayersFile != null) {
            dyncapWhiteListEnabled = true;
        }
        dyncapPlayersReloadSec = config.getInt("dyncap-whitelist-interval");
        dyncapPlayersCryptoAlgorithm = config.getString(
            "dyncap-whitelist-crypto", "AES/CBC/PKCS5Padding");
        dyncapPlayersCryptoPassword = config.getString("dyncap-whitelist-password");
        String encoded_iv = config.getString("dyncap-whitelist-iv");

//        BASE64Decoder decoder = new BASE64Decoder();
//        dyncapPlayersCryptoIv = decoder.decodeBuffer(encoded_iv);

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
			String message = String.format(
					"%d/%d players online dynamic cap %s.",
					playerCount, cap, state_message);
			log.info(message);
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
        if (dyncapPlayersFile == null) { return; }
        wlReloadTask = this.getServer().getScheduler().runTaskTimerAsynchronously(
            this,
            new Runnable() {
                @Override  
                public void run() {
                    getPlugin().ReloadDyncapWhitelist();
                }
            },
            1L,
            dyncapPlayersReloadSec * kTicksPerSec);
    }

    public void ReloadDyncapWhitelist() {
        if (dyncapPlayersFile == null) { return; }
        if (!ReloadDWLUri() && !ReloadDWLFile()) {
            ReloadDyncapWhitelistFailure();
        } else {
            dyncapPlayersReloadFailures = 0;
        }
    }

    private boolean ReloadDWLFile() {
        BufferedReader br = null;
        try {
            File f = new File(dyncapPlayersFile);
            if (!f.exists()) {
                return false;
            }
            long lastModified = f.lastModified();
            if (dyncapWLFileLastModified == lastModified) {
                return true;
            }
            dyncapWLFileLastModified = lastModified;
            br = getDWLReader(new FileReader(f));
            dyncapPlayers = LoadDWLFromReader(br);
            return true;
        } catch (Exception ex) {
            // TODO: Log failure
        } finally {
            try {
                if (br != null) { br.close(); }
            } catch (Exception ex) {
            }
        }
        return false;
    }

    private boolean ReloadDWLUri() {
        URL url = null;
        try {
            url = new URL(dyncapPlayersFile);
        } catch (Exception ex) {
            return false;
        }
        String protocol = url.getProtocol();
        if (protocol != "http" && protocol != "https" && protocol != "file") {
            return false;
        }
        BufferedReader br = null;
        try {
            URLConnection connection = url.openConnection();
            connection.setUseCaches(true);
            if (dyncapWLUrlLastModified != 0) {
                connection.setIfModifiedSince(dyncapWLUrlLastModified);
            }
            InputStreamReader isr = new InputStreamReader(
                connection.getInputStream(), "UTF-8");
            connection.connect();
            br = getDWLReader(isr);
            dyncapPlayers = LoadDWLFromReader(br);
            dyncapWLUrlLastModified = connection.getLastModified();
            return true;
        } catch (Exception ex) {
            // TODO: Log failure
        } finally {
            try {
                if (br != null) { br.close(); }
            } catch (java.io.IOException ex) {
            }
        }
        return false;
    }

    private BufferedReader getDWLReader(Reader in) {
        if (dyncapPlayersCryptoAlgorithm == null ||
            dyncapPlayersCryptoPassword == null)
        {
            return new BufferedReader(in);
        }
        log.severe("Not implemented");
        return null;
//        Cipher cipher = Cipher.getInstance(dyncapPlayersCryptoAlgorithm);
//        
//        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(dyncapPlayersCryptoIv));
//
//            CipherInputStream

    }

    private Set<String> LoadDWLFromReader(BufferedReader br) throws IOException {
        Set<String> new_players = new HashSet<String>();
        while (br.ready()) {
            String line = br.readLine().trim().toLowerCase();
            if (line.length() <= 0) { continue; }
            if (line.charAt(0) == '#') { continue; }
            new_players.add(line);
        }
        return new_players;
    }

    private boolean ReloadDyncapWhitelistFailure() {
        ++dyncapPlayersReloadFailures;
        if (dyncapPlayersReloadFailures >= kMaxFailures) {
            // TODO: Ponder failure scenarios. Should it lock down the server
            //  until a server restart?
            log.severe("DynCap WhiteList file not found");
            wlReloadTask.cancel();
            dyncapPlayersFile = null;
            return true;
        }
        return false;
    }
}
