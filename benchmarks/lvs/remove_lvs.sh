echo "Clearing IPVS table..."
ipvsadm -C 2>/dev/null || true
 
echo ""
echo "IPVS table now:"
ipvsadm -L -n 2>/dev/null || echo "  (ipvsadm reports empty / no table)"
 
echo ""
echo "Note: FORWARD policy and rp_filter sysctls were left as-is."
 
