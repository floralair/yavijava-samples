package com.vmware.vim25.mo.samples.vm;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.vmware.vim25.ClusterAction;
import com.vmware.vim25.ClusterRecommendation;
import com.vmware.vim25.PlacementAction;
import com.vmware.vim25.PlacementResult;
import com.vmware.vim25.PlacementSpec;
import com.vmware.vim25.ServiceLocator;
import com.vmware.vim25.ServiceLocatorNamePassword;
import com.vmware.vim25.VirtualDevice;
import com.vmware.vim25.VirtualDeviceConfigSpec;
import com.vmware.vim25.VirtualMachineConfigInfo;
import com.vmware.vim25.VirtualMachineConfigSpec;
import com.vmware.vim25.VirtualMachineRelocateSpec;
import com.vmware.vim25.mo.ClusterComputeResource;
import com.vmware.vim25.mo.Folder;
import com.vmware.vim25.mo.ServiceInstance;
import com.vmware.vim25.mo.Task;
import com.vmware.vim25.mo.VirtualMachine;
import com.vmware.vim25.mo.samples.SearchTool;

public class XVCvMotionUtil {

	public static void main(String[] args) throws Exception {
	    
        String sourceVcUrl = "https://*.*.*.*/sdk";
        String sourceVcUserName = "****";
        String sourceVcPassword = "****";
        String destVcUrl = "https://*.*.*.*/sdk";
        String destVcUserName = "****";
        String destVcPassword = "****"; 
        String vmName = "****";
        String destClusterName = "****";
        XVCvMotionUtil vmotionUtil = new XVCvMotionUtil();
        vmotionUtil.xVcVmotion(sourceVcUrl, sourceVcUserName, sourceVcPassword, destVcUrl, destVcUserName, destVcPassword, vmName, destClusterName);
        
	}
	
    private void xVcVmotion(String sourceVcUrl, String sourceVcUserName, String sourceVcPassword, String destVcUrl, String destVcUserName, String destVcPassword, String vmName, String destClusterName) throws Exception {
        ServiceInstance  sourceVcSi= new ServiceInstance(new URL(sourceVcUrl), sourceVcUserName, sourceVcPassword, true); 
        ServiceInstance  destVcSi= new ServiceInstance(new URL(destVcUrl), destVcUserName, destVcPassword, true);
        
        VirtualMachine vm = SearchTool.findVm(sourceVcSi, vmName);
        ClusterComputeResource destCluster = SearchTool.findCluster(destVcSi, destClusterName);
        
        PlacementSpec placeSpec = new PlacementSpec();
        VirtualMachineConfigSpec configSpec = new VirtualMachineConfigSpec();
        VirtualMachineConfigInfo configInfo = vm.getConfig();
        configSpec.setName(configInfo.getName());
        configSpec.setVersion(configInfo.getVersion());
        configSpec.setCpuAllocation(configInfo.getCpuAllocation());
        configSpec.setMemoryAllocation(configInfo.getMemoryAllocation());
        configSpec.setNumCPUs(configInfo.getHardware().getNumCPU());
        configSpec.setMemoryMB((long) configInfo.getHardware().getMemoryMB());
        configSpec.setFiles(configInfo.getFiles());
        configSpec.setSwapPlacement(configInfo.getSwapPlacement());
        VirtualDevice[] devices = configInfo.getHardware().getDevice();
        List<VirtualDeviceConfigSpec> deviceSpecList = new ArrayList<>();
        for (VirtualDevice device : devices) {
            VirtualDeviceConfigSpec spec = new VirtualDeviceConfigSpec();
            spec.setDevice(device);
            deviceSpecList.add(spec);
        }
        configSpec.setDeviceChange(deviceSpecList.toArray(new VirtualDeviceConfigSpec[deviceSpecList.size()]));
        placeSpec.setConfigSpec(configSpec);
        
        PlacementResult placResult = destCluster.placeVm(placeSpec);
        PlacementAction placementAction = getPlacementAction(placResult);
        
        ServiceLocatorNamePassword slNamePassowrd = new ServiceLocatorNamePassword();
        slNamePassowrd.setUsername(destVcUserName);
        slNamePassowrd.setPassword(destVcPassword);
        
        ServiceLocator locator = new ServiceLocator();
        locator.setCredential(slNamePassowrd);
        locator.setUrl(destVcUrl);
        locator.setInstanceUuid(destVcSi.getAboutInfo().getInstanceUuid());
        locator.setSslThumbprint(getThumbprint(destVcUrl));
        VirtualMachineRelocateSpec relocSpec = placementAction.getRelocateSpec();
        relocSpec.setService(locator);
        Folder vmFolder = SearchTool.findFolder(destVcSi, "vm");
        relocSpec.setFolder(vmFolder.getMOR());
        System.out.println("Start xVC vMotion VM: " + vmName);
        Task task = vm.relocateVM_Task(relocSpec);
        String result = task.waitForTask(200, 100); 
        System.out.println("Done xVC vMotion VM: " + vmName + " result: " + result);
    }
    
    private PlacementAction getPlacementAction(PlacementResult placementResult) throws Exception {
        ClusterRecommendation[] recommendations = placementResult.getRecommendations();
        PlacementAction placementAction = null;
        if (recommendations == null || recommendations.length == 0) {
            throw new Exception("No recommendations");
        }
        for (ClusterRecommendation recomm : recommendations) {
            if (recomm.getReason().equalsIgnoreCase("xvmotionPlacement")) {
                ClusterAction[] actions = recomm.getAction();
                for (ClusterAction action : actions) {
                    if (action instanceof PlacementAction) {
                        placementAction = (PlacementAction) action;
                        break;
                    }
                }
                if (placementAction != null) {
                    if (placementAction.getVm() == null || placementAction.getTargetHost() == null) {
                        System.out.println("Placement Action doesn't have a vm or target host set");
                    } else {
                        if (placementAction.getRelocateSpec() != null) {
                            if (checkRelocateSpec(placementAction.getRelocateSpec()))
                                break;
                            else
                                placementAction = null;
                        }
                    }
                } else {
                    System.out.println("Recommendation doesn't have a placement action");
                }                
            }
        }
        return placementAction;
    }
    
    private boolean checkRelocateSpec(VirtualMachineRelocateSpec relocateSpec) {
        boolean check = false;
        if (relocateSpec.getHost() != null) {
            if (relocateSpec.getPool() != null) {
                if (relocateSpec.getDatastore() != null) {
                    check = true;
                } else {
                    System.out.println("RelocateSpec does not have a datastore");
                }
            } else {
                System.out.println("RelocateSpec does not have a resource pool");
            }
        } else {
            System.out.println("RelocateSpec does not have a host");
        }
        return check;
    }
	
	public String getThumbprint(String vcUrl) throws Exception {
	    if (vcUrl == null || !Pattern.matches("^https://.+/sdk/?$", vcUrl)) {
	        throw new Exception("Invalid VC url.");
	    }
	    String hostStr = vcUrl.substring("https://".length(), vcUrl.lastIndexOf("/sdk"));
	    String[] hostPort = hostStr.split(":");
	    String host = hostPort[0];
	    int port = 443;
	    if (hostPort.length > 1) {
	        port = Integer.parseInt(hostPort[1]);
	    }
	    SSLSocket socket = null;
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[] { trm }, null);
            SSLSocketFactory factory = sc.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(host, port);
            socket.startHandshake();
            SSLSession session = socket.getSession();
            Certificate[] servercerts = session.getPeerCertificates();
            for (int i = 0; i < servercerts.length; i++) {
                if (servercerts[i] instanceof X509Certificate) {
                    return calcThumbprint((X509Certificate) servercerts[i]);
                }
            }
            throw new Exception("No valid thumbprint found.");
        } catch (Exception e) {
            throw e;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }       
        }        
	}
	
    private String calcThumbprint(X509Certificate cert) throws GeneralSecurityException {
        char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(cert.getEncoded());
        byte[] data = md.digest();
        int length = data.length;
        StringBuilder rtn = new StringBuilder(length * 3 - 1);
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                rtn.append(':');
            }
            rtn.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
            rtn.append(HEX_CHARS[data[i] & 0x0F]);
        }
        return rtn.toString().toUpperCase();
    }
    
    private TrustManager trm = new X509TrustManager() {
        
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
        
    };

}
