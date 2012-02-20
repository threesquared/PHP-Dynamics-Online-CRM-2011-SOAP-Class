<?php
/** 
*	Copyright (C) 2011 Ben Speakman
*	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**/

require_once('dynamicsclient.php');

$dynamicsClient = new dynamicsClient('you@org.com','password','org.crm4.dynamics.com',1);

$request = '
	<RetrieveMultiple xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services">
		<query i:type="b:QueryExpression" xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
		<b:ColumnSet>
			<b:AllColumns>false</b:AllColumns>
			<b:Columns xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
				<c:string>accountid</c:string>
				<c:string>name</c:string>
			</b:Columns>
		</b:ColumnSet>
		<b:Criteria>
			<b:Conditions />
			<b:FilterOperator>And</b:FilterOperator>
			<b:Filters />
		</b:Criteria>
		<b:Distinct>false</b:Distinct>
		<b:EntityName>account</b:EntityName>
		<b:LinkEntities />
		<b:Orders />
		<b:PageInfo>
			<b:Count>0</b:Count>
			<b:PageNumber>0</b:PageNumber>
			<b:PagingCookie i:nil="true" />
			<b:ReturnTotalRecordCount>false</b:ReturnTotalRecordCount>
		</b:PageInfo>
		</query>
	</RetrieveMultiple>';

echo $dynamicsClient->sendQuery($request);