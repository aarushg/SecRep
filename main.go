package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/jung-kurt/gofpdf"
)

func main() {
	// Check if a CSV file is provided as an argument
	var data []string
	if len(os.Args) > 1 {
		filePath := os.Args[1]
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Printf("Failed to open CSV file: %v\n", err)
			return
		}
		defer file.Close()

		reader := csv.NewReader(file)
		data, err = reader.Read()
		if err != nil {
			fmt.Printf("Failed to read CSV file: %v\n", err)
			return
		}
		if len(data) < 25 {
			fmt.Println("CSV file does not have enough columns.")
			return
		}
	} else {
		// If no CSV file provided, prompt the user for each input
		data = append(data,
			promptUser("Enter Client Name: "),
			promptUser("Enter Company Name: "),
			promptUser("Enter Contact Person: "),
			promptUser("Enter Contact Email: "),
			promptUser("Enter Contact Phone Number: "),
			promptUser("Enter Date of Report: "),
			promptUser("Enter Engagement Start Date: "),
			promptUser("Enter Engagement End Date: "),
			promptUser("Enter Total Vulnerabilities Found: "),
			promptUser("Enter High-Risk Vulnerabilities: "),
			promptUser("Enter Medium-Risk Vulnerabilities: "),
			promptUser("Enter Low-Risk Vulnerabilities: "),
			promptUser("Enter Overall Risk Level (Low/Medium/High): "),
			promptUser("Enter In-Scope Assets (IP/Hostnames, Web Apps, etc.): "),
			promptUser("Enter Out of Scope Assets: "),
			promptUser("Enter Methodology: "),
			promptUser("Enter Tools Used: "),
			promptUser("Enter Vulnerability Summary: "),
			promptUser("Enter Exploitation Details: "),
			promptUser("Enter Evidence (Screenshots/Logs): "),
			promptUser("Enter Short-Term Recommendations: "),
			promptUser("Enter Long-Term Recommendations: "),
			promptUser("Enter Basic Package Pricing: "),
			promptUser("Enter Standard Package Pricing: "),
			promptUser("Enter Premium Package Pricing: "),
			promptUser("Enter Executive Summary: "),
			promptUser("Enter Risk Assessment: "),
			promptUser("Enter Conclusion: "),
		)
	}

	// Capture packets and generate summary
	packetSummary := captureAllInterfaces()

	// Generate the PDF report and save it to a file
	err := generatePDFReport(
		data[0], data[1], data[2], data[3], data[4], data[5],
		data[6], data[7], data[8], data[9], data[10], data[11],
		data[12], data[13], data[14], data[15], data[16], data[17],
		data[18], data[19], data[20], data[21], data[22], data[23], data[24],
		data[25], data[26], data[27], packetSummary,
	)

	if err != nil {
		fmt.Printf("Failed to generate PDF report: %v\n", err)
	} else {
		fmt.Println("PDF report successfully saved to report.pdf")
	}
}

// Function to prompt the user for input
func promptUser(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input) // Remove the newline character
}

// Function to capture packets on all active network interfaces
func captureAllInterfaces() string {
	var summary strings.Builder
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to list interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			// Skip down and loopback interfaces
			continue
		}

		handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			fmt.Printf("Error opening device %s: %v\n", iface.Name, err)
			continue
		}
		defer handle.Close()

		fmt.Printf("Capturing packets on interface: %s\n", iface.Name)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		// Capture a limited number of packets for the summary
		packetCount := 0
		for packet := range packetSource.Packets() {
			summary.WriteString(fmt.Sprintf("Interface %s: Packet %d - %s\n", iface.Name, packetCount+1, packet))
			packetCount++
			if packetCount >= 5 { // Capture only a few packets per interface for summary
				break
			}
		}
	}

	return summary.String()
}

// Function to generate a PDF report and save it to a file
func generatePDFReport(clientName, companyName, contactPerson, contactEmail, contactPhone,
	dateOfReport, engagementStart, engagementEnd, totalVulnerabilities, highRisk,
	mediumRisk, lowRisk, overallRiskLevel, inScopeAssets, outOfScopeAssets, methodology,
	toolsUsed, vulnerabilitySummary, exploitationDetails, evidence,
	shortTermRecommendations, longTermRecommendations, basicPackage,
	standardPackage, premiumPackage, executiveSummary, riskAssessment, conclusion, packetSummary string) error {

	// Create a new PDF document
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(10, 10, 10)
	pdf.AddPage()

	// Title
	pdf.SetFont("Arial", "B", 24)
	pdf.Cell(0, 10, "Penetration Testing Report")
	pdf.Ln(10)

	// Executive Summary Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Executive Summary")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, executiveSummary)
	pdf.Ln(10)

	// Client Info Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Client Information")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, fmt.Sprintf("Client Name: %s", clientName))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Company Name: %s", companyName))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Contact Person: %s", contactPerson))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Contact Email: %s", contactEmail))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Contact Phone Number: %s", contactPhone))
	pdf.Ln(10)

	// Report Date
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Report Dates")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, fmt.Sprintf("Date of Report: %s", dateOfReport))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Engagement Start Date: %s", engagementStart))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Engagement End Date: %s", engagementEnd))
	pdf.Ln(10)

	// Vulnerabilities Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Vulnerabilities Summary")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, fmt.Sprintf("Total Vulnerabilities Found: %s", totalVulnerabilities))
	pdf.MultiCell(0, 10, fmt.Sprintf("High-Risk Vulnerabilities: %s", highRisk))
	pdf.MultiCell(0, 10, fmt.Sprintf("Medium-Risk Vulnerabilities: %s", mediumRisk))
	pdf.MultiCell(0, 10, fmt.Sprintf("Low-Risk Vulnerabilities: %s", lowRisk))
	pdf.MultiCell(0, 10, fmt.Sprintf("Overall Risk Level: %s", overallRiskLevel))
	pdf.Ln(10)

	// Scope Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Scope of Engagement")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, fmt.Sprintf("In-Scope Assets: %s", inScopeAssets))
	pdf.MultiCell(0, 10, fmt.Sprintf("Out of Scope Assets: %s", outOfScopeAssets))
	pdf.Ln(10)

	// Methodology Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Methodology")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, methodology)
	pdf.Ln(10)

	// Tools Used Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Tools Used")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, toolsUsed)
	pdf.Ln(10)

	// Findings Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Findings")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, fmt.Sprintf("Vulnerability Summary: %s", vulnerabilitySummary))
	pdf.MultiCell(0, 10, fmt.Sprintf("Exploitation Details: %s", exploitationDetails))
	pdf.MultiCell(0, 10, fmt.Sprintf("Evidence: %s", evidence))
	pdf.Ln(10)

	// Recommendations Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Recommendations")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, fmt.Sprintf("Short-Term Recommendations: %s", shortTermRecommendations))
	pdf.MultiCell(0, 10, fmt.Sprintf("Long-Term Recommendations: %s", longTermRecommendations))
	pdf.Ln(10)

	// Pricing Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Pricing")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, fmt.Sprintf("Basic Package Pricing: %s", basicPackage))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Standard Package Pricing: %s", standardPackage))
	pdf.Ln(6)
	pdf.Cell(0, 10, fmt.Sprintf("Premium Package Pricing: %s", premiumPackage))
	pdf.Ln(10)

	// Risk Assessment Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Risk Assessment")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, riskAssessment)
	pdf.Ln(10)

	// Conclusion Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Conclusion")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, conclusion)
	pdf.Ln(10)

	// Packet Summary Section
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Packet Capture Summary")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, packetSummary)

	// Save the PDF to a file
	return pdf.OutputFileAndClose("report.pdf")
}
