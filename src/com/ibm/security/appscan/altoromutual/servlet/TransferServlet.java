/**
 This application is for demonstration use only. It contains known application security
vulnerabilities that were created expressly for demonstrating the functionality of
application security testing tools. These vulnerabilities may present risks to the
technical environment in which the application is installed. You must delete and
uninstall this demonstration application upon completion of the demonstration for
which it is intended. 

IBM DISCLAIMS ALL LIABILITY OF ANY KIND RESULTING FROM YOUR USE OF THE APPLICATION
OR YOUR FAILURE TO DELETE THE APPLICATION FROM YOUR ENVIRONMENT UPON COMPLETION OF
A DEMONSTRATION. IT IS YOUR RESPONSIBILITY TO DETERMINE IF THE PROGRAM IS APPROPRIATE
OR SAFE FOR YOUR TECHNICAL ENVIRONMENT. NEVER INSTALL THE APPLICATION IN A PRODUCTION
ENVIRONMENT. YOU ACKNOWLEDGE AND ACCEPT ALL RISKS ASSOCIATED WITH THE USE OF THE APPLICATION.

IBM AltoroJ
(c) Copyright IBM Corp. 2008, 2013 All Rights Reserved.
 */

package com.ibm.security.appscan.altoromutual.servlet;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.ibm.security.appscan.altoromutual.util.OperationsUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

/**
 * This servlet allows to transfer funds between existing accounts
 * Servlet implementation class TransverServlet
 *
 * @author Alexei
 */
public class TransferServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static final String CSRF_ATTR = "csrfToken";
	private static final String CSRF_PARAM = "csrfToken";
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	/**
	 * Generate a fresh, cryptographically-random CSRF token to bind this
	 * user's session to state-changing requests.
	 */
	private static String generateCsrfToken() {
		byte[] tokenBytes = new byte[32];
		SECURE_RANDOM.nextBytes(tokenBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
	}

	/**
	 * Constant-time comparison to prevent timing attacks on CSRF token
	 * validation.
	 */
	private static boolean constantTimeEquals(String a, String b) {
		if (a == null || b == null) {
			return false;
		}
		byte[] aBytes = a.getBytes();
		byte[] bBytes = b.getBytes();
		if (aBytes.length != bBytes.length) {
			return false;
		}
		int result = 0;
		for (int i = 0; i < aBytes.length; i++) {
			result |= aBytes[i] ^ bBytes[i];
		}
		return result == 0;
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		if (!ServletUtil.isLoggedin(req)) {
			resp.sendRedirect("login.jsp");
			return;
		}

		// CSRF protection: ensure a CSRF token exists in the session and
		// expose it to the JSP so it can be rendered in the form.
		HttpSession session = req.getSession();
		String csrfToken = (String) session.getAttribute(CSRF_ATTR);
		if (csrfToken == null) {
			csrfToken = generateCsrfToken();
			session.setAttribute(CSRF_ATTR, csrfToken);
		}
		req.setAttribute(CSRF_ATTR, csrfToken);

		RequestDispatcher dispatcher = req.getRequestDispatcher("transfer.jsp");
		dispatcher.forward(req, resp);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {


		if(!ServletUtil.isLoggedin(request)){
			response.sendRedirect("login.jsp");
			return ;
		}

		// CSRF protection: validate the token from the request against the
		// one bound to the user's session. This blocks cross-site forged
		// POSTs because the attacker cannot read the per-session token.
		HttpSession session = request.getSession();
		String sessionToken = (String) session.getAttribute(CSRF_ATTR);
		String requestToken = request.getParameter(CSRF_PARAM);
		if (!constantTimeEquals(sessionToken, requestToken)) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
			return;
		}

		String accountIdString = request.getParameter("fromAccount");
		long creditActId = Long.parseLong(request.getParameter("toAccount"));
		double amount = Double.valueOf(request.getParameter("transferAmount"));


		String message = OperationsUtil.doServletTransfer(request,creditActId,accountIdString,amount);

		RequestDispatcher dispatcher = request.getRequestDispatcher("transfer.jsp");
		request.setAttribute("message", message);
		dispatcher.forward(request, response);
	}

}
