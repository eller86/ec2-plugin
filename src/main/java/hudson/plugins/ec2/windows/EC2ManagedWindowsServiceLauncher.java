package hudson.plugins.ec2.windows;

import static hudson.Util.copyStreamAndClose;
import static org.jvnet.hudson.wmi.Win32Service.Win32OwnProcess;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jenkins.model.Jenkins;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.jinterop.dcom.common.JIDefaultAuthInfoImpl;
import org.jinterop.dcom.common.JIException;
import org.jinterop.dcom.core.JISession;
import org.jvnet.hudson.remcom.WindowsRemoteProcessLauncher;
import org.jvnet.hudson.wmi.SWbemServices;
import org.jvnet.hudson.wmi.WMI;
import org.jvnet.hudson.wmi.Win32Service;
import org.kohsuke.stapler.DataBoundConstructor;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.ec2.model.Instance;

import hudson.lifecycle.WindowsSlaveInstaller;
import hudson.model.TaskListener;
import hudson.os.windows.Messages;
import hudson.os.windows.WindowsRemoteFileSystem;
import hudson.os.windows.WindowsRemoteLauncher;
import hudson.plugins.ec2.EC2ComputerLauncher;
import hudson.plugins.ec2.EC2Computer;
import hudson.remoting.Channel;
import hudson.remoting.SocketInputStream;
import hudson.remoting.SocketOutputStream;
import hudson.remoting.Channel.Listener;
import hudson.slaves.SlaveComputer;
import hudson.tools.JDKInstaller;
import hudson.tools.JDKInstaller.CPU;
import hudson.tools.JDKInstaller.Platform;
import hudson.util.IOUtils;
import hudson.util.Secret;
import hudson.util.jna.DotNet;

public class EC2ManagedWindowsServiceLauncher extends EC2ComputerLauncher {

    private final int FAILED=-1;
    private final int SAMEUSER=0;
    private final int RECONNECT=-2;

    public final String userName;
    public final Secret password;
    public String host;

    @DataBoundConstructor
    public EC2ManagedWindowsServiceLauncher(String userName, Secret password) {
        this.userName = userName;
        this.password = password;
    }

	@Override
	protected void launch(EC2Computer computer, TaskListener listener,
			Instance inst) throws AmazonClientException, IOException,
			InterruptedException {
		// TODO 自動生成されたメソッド・スタブ
		this.host = getHostName(computer);
		wmiLaunch(computer, listener);
	}


	private String getHostName(EC2Computer computer) throws AmazonClientException, InterruptedException{
		Instance instance;
		instance = computer.updateInstanceDescription();
		 String vpc_id = instance.getVpcId();
	        String host;

	        if (computer.getNode().usePrivateDnsName) {
	            host = instance.getPrivateDnsName();
	        } else {
	            /* VPC hosts don't have public DNS names, so we need to use an IP address instead */
	            if (vpc_id == null || vpc_id.equals("")) {
	                host = instance.getPublicDnsName();
	            } else {
	                host = instance.getPrivateIpAddress();
	            }
	        }
	        return host;
	}


	private void wmiLaunch(final EC2Computer computer, final TaskListener listener)  throws IOException, InterruptedException {
		try {
            final PrintStream logger = listener.getLogger();
            final String name = host;

            logger.println(Messages.ManagedWindowsServiceLauncher_ConnectingTo(name));

            InetAddress host = InetAddress.getByName(name);

            try {
                Socket s = new Socket();
                s.connect(new InetSocketAddress(host,135),5000);
                s.close();
            } catch (IOException e) {
                logger.println("Failed to connect to port 135 of "+name+". Is Windows firewall blocking this port? Or did you disable DCOM service?");
                // again, let it continue.
            }

            JIDefaultAuthInfoImpl auth = createAuth();
            JISession session = JISession.createSession(auth);
            session.setGlobalSocketTimeout(60000);
            SWbemServices services = WMI.connect(session, name);


            String path = computer.getNode().getRemoteFS();
            if (path.indexOf(':')==-1)   throw new IOException("Remote file system root path of the slave needs to be absolute: "+path);
            SmbFile remoteRoot = new SmbFile("smb://" + name + "/" + path.replace('\\', '/').replace(':', '$')+"/",createSmbAuth());

            if(!remoteRoot.exists())
                remoteRoot.mkdirs();

            try {// does Java exist?
                logger.println("Checking if Java exists");
                WindowsRemoteProcessLauncher wrpl = new WindowsRemoteProcessLauncher(name,auth);
                Process proc = wrpl.launch("java -fullversion","c:\\");
                proc.getOutputStream().close();
                IOUtils.copy(proc.getInputStream(),logger);
                proc.getInputStream().close();
                int exitCode = proc.waitFor();
                if (exitCode==1) {// we'll get this error code if Java is not found
                    logger.println("No Java found. Downloading JDK");
                    JDKInstaller jdki = new JDKInstaller("jdk-6u16-oth-JPR@CDS-CDS_Developer",true);
                    URL jdk = jdki.locate(listener, Platform.WINDOWS, CPU.i386);

                    listener.getLogger().println("Installing JDK");
                    copyStreamAndClose(jdk.openStream(), new SmbFile(remoteRoot, "jdk.exe").getOutputStream());

                    String javaDir = path + "\\jdk"; // this is where we install Java to

                    WindowsRemoteFileSystem fs = new WindowsRemoteFileSystem(name, createSmbAuth());
                    fs.mkdirs(javaDir);

                    jdki.install(new WindowsRemoteLauncher(listener,wrpl), Platform.WINDOWS,
                            fs, listener, javaDir ,path+"\\jdk.exe");
                }
            } catch (Exception e) {
                e.printStackTrace(listener.error("Failed to prepare Java"));
            }

            String id = WindowsSlaveInstaller.generateServiceId(path);
            Win32Service slaveService = services.getService(id);
            if(slaveService==null) {
                logger.println(Messages.ManagedWindowsServiceLauncher_InstallingSlaveService());
                if(!DotNet.isInstalled(2,0, name, auth)) {
                    // abort the launch
                    logger.println(Messages.ManagedWindowsServiceLauncher_DotNetRequired());
                    return;
                }

                // copy exe
                logger.println(Messages.ManagedWindowsServiceLauncher_CopyingSlaveExe());
                copyStreamAndClose(getClass().getResource("/windows-service/jenkins.exe").openStream(), new SmbFile(remoteRoot,"jenkins-slave.exe").getOutputStream());

                copySlaveJar(logger, remoteRoot);

                // copy jenkins-slave.xml
                logger.println(Messages.ManagedWindowsServiceLauncher_CopyingSlaveXml());
                String xml = WindowsSlaveInstaller.generateSlaveXml(id,"javaw.exe","-tcp %BASE%\\port.txt");
                copyStreamAndClose(new ByteArrayInputStream(xml.getBytes("UTF-8")), new SmbFile(remoteRoot,"jenkins-slave.xml").getOutputStream());

                // install it as a service
                logger.println(Messages.ManagedWindowsServiceLauncher_RegisteringService());
                Document dom = new SAXReader().read(new StringReader(xml));
                Win32Service svc = services.Get("Win32_Service").cast(Win32Service.class);
                int r = svc.Create(
                        id,
                        dom.selectSingleNode("/service/name").getText()+" at "+path,
                        path+"\\jenkins-slave.exe",
                        Win32OwnProcess, 0, "Manual", true);
                if(r!=0) {
                    listener.error("Failed to create a service: "+svc.getErrorMessage(r));
                    return;
                }
                slaveService = services.getService(id);
            } else {
                copySlaveJar(logger, remoteRoot);
            }

            logger.println(Messages.ManagedWindowsServiceLauncher_StartingService());
            slaveService.start();

            // wait until we see the port.txt, but don't do so forever
            logger.println(Messages.ManagedWindowsServiceLauncher_WaitingForService());
            SmbFile portFile = new SmbFile(remoteRoot, "port.txt");
            for( int i=0; !portFile.exists(); i++ ) {
                if(i>=30) {
                    listener.error(Messages.ManagedWindowsServiceLauncher_ServiceDidntRespond());
                    return;
                }
                Thread.sleep(1000);
            }
            int p = readSmbFile(portFile);

            // connect
            logger.println(Messages.ManagedWindowsServiceLauncher_ConnectingToPort(p));
            final Socket s = new Socket(name,p);

            // ready
            computer.setChannel(new BufferedInputStream(new SocketInputStream(s)),
                new BufferedOutputStream(new SocketOutputStream(s)),
                listener.getLogger(),new Listener() {
                    @Override
                    public void onClosed(Channel channel, IOException cause) {
                        afterDisconnect(computer,listener);
                    }
                });
            //destroy session to free the socket
            JISession.destroySession(session);
        } catch (SmbException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        } catch (JIException e) {
            if(e.getErrorCode()==5)
                // access denied error
                e.printStackTrace(listener.error(Messages.ManagedWindowsServiceLauncher_AccessDenied()));
            else
                e.printStackTrace(listener.error(e.getMessage()));
        } catch (DocumentException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        }

	}

	private JIDefaultAuthInfoImpl createAuth() {
        String[] tokens = userName.split("\\\\");
        if(tokens.length==2)
            return new JIDefaultAuthInfoImpl(tokens[0], tokens[1], Secret.toString(password));
        return new JIDefaultAuthInfoImpl("", userName, Secret.toString(password));
    }

	private NtlmPasswordAuthentication createSmbAuth() {
        JIDefaultAuthInfoImpl auth = createAuth();
        return new NtlmPasswordAuthentication(auth.getDomain(), auth.getUserName(), auth.getPassword());
    }
	private void copySlaveJar(PrintStream logger, SmbFile remoteRoot) throws IOException {
        // copy slave.jar
        logger.println("Copying slave.jar");
        copyStreamAndClose(Jenkins.getInstance().getJnlpJars("slave.jar").getURL().openStream(), new SmbFile(remoteRoot,"slave.jar").getOutputStream());
    }

    private int readSmbFile(SmbFile f) throws IOException {
        InputStream in=null;
        try {
            in = f.getInputStream();
            return Integer.parseInt(IOUtils.toString(in));
        } finally {
            IOUtils.closeQuietly(in);
        }
    }

    @Override
    public void afterDisconnect(SlaveComputer computer, TaskListener listener) {
        try {
            JIDefaultAuthInfoImpl auth = createAuth();
            JISession session = JISession.createSession(auth);
            session.setGlobalSocketTimeout(60000);
            SWbemServices services = WMI.connect(session, computer.getName());
            Win32Service slaveService = services.getService("jenkinsslave");
            if(slaveService!=null) {
                listener.getLogger().println(Messages.ManagedWindowsServiceLauncher_StoppingService());
                slaveService.StopService();
            }
            //destroy session to free the socket
            JISession.destroySession(session);
        } catch (UnknownHostException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        } catch (JIException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        }
    }
}
