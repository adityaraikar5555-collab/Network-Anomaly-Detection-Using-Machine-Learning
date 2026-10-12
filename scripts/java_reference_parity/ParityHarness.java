import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.IdGenerator;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal extracted harness that drives the real, unmodified CICFlowMeter
 * {@code BasicFlow} implementation.
 *
 * The reference sources compiled alongside this harness are taken verbatim from
 * ahlashkari/CICFlowMeter @ 98a5ebad0df579cc8b43eedd3421b3ae87699901:
 *
 *   src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java
 *   src/main/java/cic/cs/unb/ca/jnetpcap/BasicPacketInfo.java
 *   src/main/java/cic/cs/unb/ca/jnetpcap/IdGenerator.java
 *   src/main/java/cic/cs/unb/ca/jnetpcap/DateFormatter.java
 *
 * Packet capture / jnetpcap parsing is NOT exercised. {@link BasicPacketInfo}
 * is populated programmatically so the feature arithmetic under test is the
 * reference arithmetic. This harness therefore validates the reference
 * <em>feature computation</em>, not the reference's packet decoder.
 *
 * Packet ordering and the per-packet driver mirror
 * {@code FlowGenerator.addPacket}'s normal (no-FIN / no-RST) path:
 *
 *   flow.updateActiveIdleTime(currentTimestamp, activityTimeout);
 *   flow.addPacket(packet);
 *
 * Usage: {@code java ParityHarness <scenario.csv>}
 */
public class ParityHarness {

    // From cic.cs.unb.ca.jnetpcap.ifm.Cmd: activityTimeout = 5 s (microseconds).
    private static final long ACTIVITY_TIMEOUT = 5000000L;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ParityHarness <scenario.csv>");
            System.exit(2);
        }
        List<BasicPacketInfo> packets = readScenario(args[0], new IdGenerator());
        if (packets.isEmpty()) {
            System.err.println("scenario has no packets");
            System.exit(2);
        }

        BasicFlow flow = new BasicFlow(true, packets.get(0), ACTIVITY_TIMEOUT);
        for (int i = 1; i < packets.size(); i++) {
            BasicPacketInfo p = packets.get(i);
            flow.updateActiveIdleTime(p.getTimeStamp(), ACTIVITY_TIMEOUT);
            flow.addPacket(p);
        }

        System.out.println("packet_count=" + flow.packetCount());

        System.out.println("Active Mean=" + flow.getActiveMean());
        System.out.println("Active Std=" + flow.getActiveStd());
        System.out.println("Active Max=" + flow.getActiveMax());
        System.out.println("Active Min=" + flow.getActiveMin());
        System.out.println("Idle Mean=" + flow.getIdleMean());
        System.out.println("Idle Std=" + flow.getIdleStd());
        System.out.println("Idle Max=" + flow.getIdleMax());
        System.out.println("Idle Min=" + flow.getIdleMin());

        System.out.println("Fwd Avg Bytes/Bulk=" + flow.fAvgBytesPerBulk());
        System.out.println("Fwd Avg Packets/Bulk=" + flow.fAvgPacketsPerBulk());
        System.out.println("Fwd Avg Bulk Rate=" + flow.fAvgBulkRate());
        System.out.println("Bwd Avg Bytes/Bulk=" + flow.bAvgBytesPerBulk());
        System.out.println("Bwd Avg Packets/Bulk=" + flow.bAvgPacketsPerBulk());
        System.out.println("Bwd Avg Bulk Rate=" + flow.bAvgBulkRate());
    }

    private static List<BasicPacketInfo> readScenario(String path, IdGenerator gen)
            throws Exception {
        List<BasicPacketInfo> packets = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line = br.readLine(); // header
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                String[] c = line.split(",");
                byte[] src = ip(c[0]);
                byte[] dst = ip(c[1]);
                int srcPort = Integer.parseInt(c[2]);
                int dstPort = Integer.parseInt(c[3]);
                int protocol = Integer.parseInt(c[4]);
                long ts = Long.parseLong(c[5]);
                long payload = Long.parseLong(c[6]);
                long header = Long.parseLong(c[7]);

                BasicPacketInfo p =
                        new BasicPacketInfo(src, dst, srcPort, dstPort, protocol, ts, gen);
                p.setPayloadBytes(payload);
                p.setHeaderBytes(header);
                p.setFlagFIN(bit(c[8]));
                p.setFlagSYN(bit(c[9]));
                p.setFlagRST(bit(c[10]));
                p.setFlagPSH(bit(c[11]));
                p.setFlagACK(bit(c[12]));
                p.setFlagURG(bit(c[13]));
                p.setFlagCWR(bit(c[14]));
                p.setFlagECE(bit(c[15]));
                p.setTCPWindow(Integer.parseInt(c[16]));
                packets.add(p);
            }
        }
        return packets;
    }

    private static boolean bit(String s) {
        return "1".equals(s);
    }

    private static byte[] ip(String dotted) {
        String[] parts = dotted.split("\\.");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = (byte) Integer.parseInt(parts[i]);
        }
        return out;
    }
}
