// Script to verify the compatibility of libraries with Bun
// This script attempts to import and test the main dependencies

import fs from 'fs';
import path from 'path';

console.log("Verifying compatibility with Bun v1.2.10...");
console.log(`Bun Version: ${Bun.version}`);
console.log(`Using server.js (ESM compatible)`);

// Function to test imports
async function testImports() {
  try {
    // List of modules to test
    const modules = [
      "express",
      "bcryptjs",
      "body-parser",
      "sqlite3",
      "dotenv",
      "ejs",
      "express-session",
      "connect-sqlite3",
      "helmet",
      "jsonwebtoken",
      "qrcode",
      "speakeasy",
      "shelljs"
    ];
    
    // Verify each module
    for (const module of modules) {
      try {
        // Dynamically import the module
        const mod = await import(module);
        console.log(`✅ ${module}: Successfully imported`);
      } catch (error) {
        console.error(`❌ ${module}: Import error - ${error.message}`);
      }
    }
    
    // Test SQLite database access
    try {
      const sqlite3 = await import('sqlite3');
      const { Database } = sqlite3.default;
      
      const db = new Database(':memory:', (err) => {
        if (err) {
          console.error(`❌ SQLite: Error creating in-memory database - ${err.message}`);
        } else {
          console.log(`✅ SQLite: In-memory database created successfully`);
          
          // Test query execution
          db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)", (err) => {
            if (err) {
              console.error(`❌ SQLite: Error executing query - ${err.message}`);
            } else {
              console.log(`✅ SQLite: Query executed successfully`);
            }
            
            // Close the database
            db.close();
          });
        }
      });
    } catch (error) {
      console.error(`❌ SQLite: General error - ${error.message}`);
    }
    
  } catch (error) {
    console.error(`General error: ${error.message}`);
  }
}

// Run the tests
testImports(); 